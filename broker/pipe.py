"""Broker-owned Chromium over the DevTools pipe.

In this mode the broker spawns and owns the browser itself and speaks CDP over
file descriptors 3/4. There is no TCP debugging port at all, so the browser
channel belongs exclusively to the broker process. CDP messages are JSON
terminated by a NUL byte.
"""

from __future__ import annotations

import json
import os
import select
import shutil
import subprocess
import tempfile
import threading
import time


class PipeError(Exception):
    """Failure safe to surface; never contains the password."""


# Chrome's pipe messages are bounded; a malformed peer must not grow our buffer
# without limit. One fd-3/4 setup at a time: the parent temporarily owns 3/4.
_MAX_MESSAGE_BYTES = 1024 * 1024
_START_LOCK = threading.Lock()


class PipeTransport:
    """A long-lived, broker-owned browser speaking CDP over a pipe."""

    def __init__(self, browser: str, args: tuple[str, ...] = (), timeout: float = 15.0):
        self.browser = browser
        self.args = tuple(args)
        self.timeout = timeout
        self._lock = threading.Lock()
        self._session_lock = threading.Lock()
        self._buf = b""
        self._next_id = 0
        self._sessions: dict[str, str] = {}
        self._profile = tempfile.mkdtemp(prefix="hermes-vault-cdp-")
        self._proc: subprocess.Popen | None = None
        self._w: int | None = None
        self._r: int | None = None
        try:
            self._start()
            # A round trip proves the browser is up before any fill is attempted.
            self.command("Browser.getVersion")
        except Exception:
            self.close()
            raise

    def _start(self) -> None:
        with _START_LOCK:
            self._start_unlocked()

    def _start_unlocked(self) -> None:
        to_browser_r, to_browser_w = os.pipe()
        from_browser_r, from_browser_w = os.pipe()
        saved: dict[int, int | None] = {}
        # Chrome reads its CDP commands from fd 3 and writes replies to fd 4.
        for fd in (3, 4):
            try:
                saved[fd] = os.dup(fd)
            except OSError:
                saved[fd] = None
        cmd = [
            self.browser, "--headless=new", "--no-sandbox", "--disable-gpu",
            "--disable-dev-shm-usage", "--user-data-dir=" + self._profile,
            "--remote-debugging-pipe",
        ] + list(self.args)
        try:
            os.dup2(to_browser_r, 3, inheritable=True)
            os.dup2(from_browser_w, 4, inheritable=True)
            self._proc = subprocess.Popen(
                cmd, pass_fds=(3, 4),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except OSError as exc:
            raise PipeError("cannot start the broker-owned browser") from exc
        finally:
            for fd, backup in saved.items():
                try:
                    if backup is not None:
                        os.dup2(backup, fd)
                        os.close(backup)
                    else:
                        os.close(fd)
                except OSError:
                    pass
        os.close(to_browser_r)
        os.close(from_browser_w)
        self._w = to_browser_w
        self._r = from_browser_r

    def _read_message(self, deadline: float) -> dict:
        fd = self._r
        if fd is None:
            raise PipeError("the browser is not running")
        while b"\0" not in self._buf:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PipeError("the browser did not answer in time")
            ready, _, _ = select.select([fd], [], [], remaining)
            if not ready:
                raise PipeError("the browser did not answer in time")
            chunk = os.read(fd, 65536)
            if not chunk:
                raise PipeError("the browser closed the pipe")
            self._buf += chunk
            if len(self._buf) > _MAX_MESSAGE_BYTES:
                raise PipeError("the browser sent an oversized message")
        raw, self._buf = self._buf.split(b"\0", 1)
        try:
            return json.loads(raw)
        except ValueError as exc:
            raise PipeError("the browser sent an unreadable message") from exc

    def command(
        self,
        method: str,
        params: dict | None = None,
        session_id: str | None = None,
        timeout: float | None = None,
    ) -> dict:
        if self._w is None or self._r is None:
            raise PipeError("the browser is not running")
        with self._lock:
            self._next_id += 1
            message: dict = {"id": self._next_id, "method": method}
            if params:
                message["params"] = params
            if session_id:
                message["sessionId"] = session_id
            try:
                os.write(self._w, json.dumps(message).encode("utf-8") + b"\0")
            except OSError as exc:
                raise PipeError("cannot write to the browser pipe") from exc
            deadline = time.monotonic() + (timeout if timeout is not None else self.timeout)
            while time.monotonic() < deadline:
                reply = self._read_message(deadline)
                if reply.get("id") == self._next_id:
                    if "error" in reply:
                        return {"error": reply["error"]}
                    return reply.get("result", {})
            raise PipeError("the browser did not answer %s" % method)

    def list_tabs(self) -> list[dict]:
        result = self.command("Target.getTargets")
        tabs = []
        for info in result.get("targetInfos", []):
            if info.get("type") == "page":
                tabs.append({
                    "type": "page",
                    "url": info.get("url", ""),
                    "id": info.get("targetId"),
                })
        return tabs

    def _attach(self, tab_id: str) -> str:
        """Reuse one flattened session per tab instead of leaking a new one."""
        with self._session_lock:
            session_id = self._sessions.get(tab_id)
            if session_id:
                return session_id
            attached = self.command(
                "Target.attachToTarget", {"targetId": tab_id, "flatten": True}
            )
            session_id = attached.get("sessionId")
            if not session_id:
                raise PipeError("could not attach to the page")
            self._sessions[tab_id] = session_id
            return session_id

    def _call_in_page(
        self, tab_id: str, method: str, params: dict, timeout: float | None = None
    ) -> dict:
        result: dict = {}
        for _ in range(2):
            session_id = self._attach(tab_id)
            result = self.command(method, params, session_id=session_id, timeout=timeout)
            if "error" not in result:
                return result
            # A closed tab leaves its session stale; attach once more.
            with self._session_lock:
                self._sessions.pop(tab_id, None)
        return result

    def evaluate(self, tab_id: str, expression: str) -> dict:
        result = self._call_in_page(
            tab_id,
            "Runtime.evaluate",
            {"expression": expression, "returnByValue": True, "awaitPromise": True},
        )
        if "error" in result:
            return {"error": result["error"]}
        return {"id": 1, "result": result}

    def navigate(self, tab_id: str, url: str) -> None:
        """Point one of our tabs at a URL and wait for the document to arrive."""
        try:
            self._call_in_page(tab_id, "Page.navigate", {"url": url}, timeout=3.0)
        except PipeError:
            # A navigation reply can arrive after its load events. The poll
            # below is the check that matters.
            with self._session_lock:
                self._sessions.pop(tab_id, None)
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            result = self._call_in_page(
                tab_id,
                "Runtime.evaluate",
                {"expression": "document.location.href", "returnByValue": True},
            )
            href = result.get("result", {}).get("value")
            if isinstance(href, str) and href.rstrip("/") == url.rstrip("/"):
                return
            time.sleep(0.15)
        raise PipeError("the page did not reach its destination")

    def close(self) -> None:
        self._sessions.clear()
        if self._proc is not None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            self._proc = None
        for attr in ("_w", "_r"):
            fd = getattr(self, attr)
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
                setattr(self, attr, None)
        shutil.rmtree(self._profile, ignore_errors=True)

    def __del__(self):  # pragma: no cover - interpreter shutdown
        try:
            self.close()
        except Exception:
            pass
