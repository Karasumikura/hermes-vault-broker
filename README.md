# hermes-vault-broker

**An out-of-process credential broker for Hermes Agent: the agent asks, the broker fills, the key never enters the agent's domain.**

Hermes can already save a login and fill it. That keeps the password out of the model's transcript — but the key that decrypts the vault still sits next to its ciphertext, inside the same trust domain as the agent that also runs `terminal`. This plugin removes that: the credentials live behind a socket, in a process that runs as its own user, holds the key in locked memory, and performs the page write itself.

---

## Why the key belongs in its own trust domain

Encryption protects a stored file, not a running agent. In the default layout the ciphertext and its key share one directory, so a single prompt injection that reaches the `terminal` tool owns the whole vault:

```
$ cat ~/.hermes/vault/vault.key
$ python -c "...Fernet(key).decrypt(open('vault.json.enc','rb').read())"
decrypted: 1 item (label=kaggle, password=8 chars)
```

This plugin removes the key from that reach. The data key is unwrapped from a passphrase-derived key at boot and held in an `mlock`'d, zeroable buffer inside the broker process, with the lock checked on every unlock. The disk holds a wrapped key and ciphertext, nothing more. No backup, sync folder, swap file or log can yield it. The broker itself never opens Hermes's credential stores — migration takes a JSON export the operator made themselves.

The write path moves as well. Today the agent resolves the password and injects it. Here the agent sends only `(handle, origin)` over a Unix socket, the broker performs the CDP write itself, and the agent receives a fill count. The plaintext never enters the agent process — not "trusted not to look", but absent.

This follows the principle Hermes' own architecture states — the only security boundary against an adversarial LLM is the operating system — and the shape Muse (Meta's personal agent) uses in production:

- `hatch-authd` keeps credentials in a separate security domain inside the VM
- `privsep` workers hold connector privileges the agent never receives
- `Sentinel` substitutes a surrogate token at the network boundary, so "the agent never sees real tokens"
- approvals are capabilities bound to destination and purpose, one-time or time-bounded

Muse's framing is the same one: *"two isolated security domains on one box, not an LLM powered agent with root."* NVIDIA OpenShell — already recommended by `SECURITY.md` — does the same from a Provider store whose credentials *"never touch the sandbox filesystem."*

`vault.key_storage: keychain` moved the key out of the filesystem; this moves it out of the agent's domain. The two compose.

---

## How it works

```
   agent process (Hermes)
        │   vault_broker_fill(handle, origin)
        ▼
   AF_UNIX /run/hermes-vault-broker/sock        ← SO_PEERCRED, 0660 vaultd:vaultd
        │                                        gateway uid: status/list/fill only
        ▼
   hermes-vault-broker   (User=vaultd, ProtectHome=yes, ProtectSystem=strict)
        │   KEK = scrypt(passphrase)   →  DEK in an mlock'd buffer
        │   origin must equal the item's bound origin, exactly
        │   DevTools endpoint from /etc/hermes-vault-broker/cdp.json (root-owned)
        ▼
   Chrome DevTools Protocol (loopback, configured port)
        └─ the broker writes the field and submits, returns {filled, submitted}
```

The agent's tool result is a count. There is no code path that returns the password.

### The DevTools endpoint is pinned by the broker

`cdp` is not a tool parameter. The endpoint is fixed by the broker and checked at every step:

- **removed** from `vault_broker_fill`'s schema (which also sets `additionalProperties: false`) and from the socket request; a request containing `cdp` is refused outright
- **read by the broker** from `/etc/hermes-vault-broker/cdp.json`, a root-owned file the service user can read but not write (`root:vaultd 0640`, no symlink, not group/world-writable — all checked at startup; a bad config stops the daemon)
- **validated as loopback** (`http` + IPv4 loopback + explicit port, no path/query/userinfo)
- **re-checked against the tab**: any `webSocketDebuggerUrl` whose `host:port` differs from the configured endpoint is refused before anything is sent. The websocket URL is rebuilt from the validated IP literal, redirects are refused, and the connection bypasses environment proxies entirely.

### Broker-owned browser (CDP pipe)

The same root-owned config can place the browser channel itself inside the trust domain:

```json
{"mode": "pipe", "browser": "/usr/bin/chromium", "args": ["about:blank"]}
```

The broker then launches and owns Chromium and speaks CDP over file descriptors 3/4 of that process. There is no TCP debugging port, no `/json/list` endpoint and no websocket URL: tabs are addressed by target id inside the broker's own browser. When a credential is filled, the broker opens that credential's bound origin in its own browser — the destination comes from the store, not from the model. Every pipe message is bounded and each tab keeps a single DevTools session. The same exact-origin check, native value setter, `input`/`change` events and `requestSubmit()` path apply. `broker/pipe.py` is covered by real Chromium round trips that navigate to a page, write a password into a live input field, and re-assert the origin inside the page before writing.

### Wire format

One JSON object per line, one request per connection:

| op | request | reply | who may call |
|---|---|---|---|
| `status` | — | `{"ok", "unlocked", "items"}` | gateway + admins |
| `list` | — | `{"ok", "items": [{handle, label, origin, identifier, ...}]}` | gateway + admins |
| `fill` | `handle, origin, submit?` | `{"ok", "filled", "submitted"}` | gateway + admins |
| `unlock` | `passphrase` | `{"ok"}` | root / vaultd only |
| `lock` | — | `{"ok"}` | root / vaultd only |
| `init` | `passphrase` | `{"ok"}` | root / vaultd only |
| `add` | `label, origin, identifier_type, identifier, password` | `{"ok", "handle"}` | root / vaultd only |
| `remove` | `handle` | `{"ok", "removed"}` | root / vaultd only |

Identifiers are metadata, not secrets: the agent may read them and type them. Only the password is sealed.

---

## Install

```bash
git clone https://github.com/Karasumikura/hermes-vault-broker
cd hermes-vault-broker
sudo HERMES_USER=<user-running-the-gateway> ./scripts/install.sh
```

`install.sh` creates the `vaultd` system user, installs the tree to `/opt/hermes-vault-broker` with its own venv, generates a self-signed certificate for the unlock page, writes the root-owned config, and enables `hermes-vault-broker.service`. It adds `HERMES_USER` to the `vaultd` group (so the 0660 socket is reachable) and writes its uid into `BROKER_ALLOW_UID`; the unit passes that as `--allow-uid`. **Restart the gateway afterwards** so the new group membership takes effect.

Defaults: `CDP_HOST=127.0.0.1`, `CDP_PORT=9223`, `SERVICE_USER=vaultd`. Re-running preserves an operator-edited `cdp.json`.

Then:

```bash
# 1. create the store — asks twice, stores neither the passphrase nor a key derived from it
sudo -u vaultd /opt/hermes-vault-broker/venv/bin/python -m broker --state /var/lib/hermes-vault-broker/store.json init

# 2. unlock it for this session: a one-time HTTPS page, works on a phone
sudo -u vaultd /opt/hermes-vault-broker/venv/bin/python -m broker unlock-form \
  --cert /var/lib/hermes-vault-broker/tls/server.crt \
  --key  /var/lib/hermes-vault-broker/tls/server.key \
  --port 58104 --host 0.0.0.0 --public-url https://<host>:58104

# 3. add a login (reads the password from the terminal, never from argv)
sudo -u vaultd /opt/hermes-vault-broker/venv/bin/python -m broker add \
  --label kaggle --origin https://www.kaggle.com --identifier you@example.com
```

To import existing logins, export them yourself first and pass the file:

```bash
sudo -u vaultd /opt/hermes-vault-broker/venv/bin/python -m broker migrate \
  --json my-export.json
```

`my-export.json` is `{"items": [{"label", "origin", "identifier", "secret": {"password"}}]}`.

## Use

```bash
hermes plugins install /opt/hermes-vault-broker/plugin
```

The plugin registers three tools:

| tool | what it does |
|---|---|
| `vault_broker_status` | unlocked? how many logins |
| `vault_broker_list` | handles, labels, bound origins, identifiers |
| `vault_broker_fill` | writes the password into the open tab and optionally submits |

Typical turn: open the login page with the browser tools, then

```json
{"handle": "vault_d4f81b2c9e10", "origin": "https://www.kaggle.com", "submit": true}
```

→ `{"ok": true, "filled": 1, "submitted": true}`

The broker reports each outcome distinctly and writes only on an exact origin match.

---

## What you get

- **Zero key material on disk.** Passphrase → scrypt → KEK → wrapped DEK; the plaintext key exists only in the broker's `mlock`'d memory.
- **The agent never holds a password.** Socket in `(handle, origin)`, count out.
- **The agent cannot choose the destination.** The DevTools endpoint comes from a root-owned config, is checked as loopback, and the tab's websocket must match it exactly.
- **A real boundary between processes.** `vaultd` runs with `ProtectHome=yes` and `ProtectSystem=strict`; it cannot read the agent's home or Hermes's credential stores.
- **Exact-origin binding, re-asserted in the page.** The origin is checked on the way in and again inside the tab immediately before the write, so a navigation between check and fill writes nothing.
- **Peer-credential + per-op checks.** The gateway uid gets `status/list/fill`; unlocking and mutation stay with root and the broker's own uid.
- **One broker for every profile.** No more per-profile vault copies, no re-adding the same login per profile.
- **A short dependency list.** `cryptography` and `websockets`, nothing else.

---

## Design notes

**Crypto.** AES-256-GCM in two layers: the data key is wrapped by a passphrase-derived key, and the item body is encrypted with the data key. Both nonces are stored; neither key is. KDF parameters live in the file so the cost can be raised later without invalidating a store.

**Memory.** `LimitMEMLOCK` in the unit plus a checked `ctypes` `mlock` call keeps the DEK out of swap. A failed lock returns a fatal `VaultError` rather than continuing unlocked. The buffer is zeroed and `munlock`ed on `lock()`; the scrypt KEK is a wipeable `bytearray` that is cleared immediately after use.

**Unlock.** The broker starts locked and stays locked until someone types the passphrase into the one-time page. That page carries a single-use random token, disables request logging (the URL carries the token), sends `no-store`, and exits after one successful submission. Wrong passphrases hit a brake: five failures pause `unlock` for a minute.

**Fill.** The broker lists DevTools targets from its configured endpoint, rejects a websocket on any other host:port, and evaluates one self-contained script that re-checks `window.location.origin`, writes through the native `HTMLInputElement` value setter (so React-controlled inputs see it), dispatches `input` and `change`, and optionally calls `requestSubmit()`. The reply is a count.

**Every outcome is explicit.** The broker reports each result distinctly and writes only on an exact origin match with a validated websocket.

---

## Development

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
```

Stdlib `unittest` only: crypto round-trips, wrong passphrase, lock semantics, on-disk plaintext absence, origin refusal, peer-uid and per-op rejection, mlock failure handling, DevTools endpoint and websocket validation, redirect refusal, config ownership checks, and a real AF_UNIX round trip.

## Compatibility

Linux. The broker needs `AF_UNIX`, `SO_PEERCRED`, `mlock` and systemd user/state directories; the CDP client needs a browser started with `--remote-debugging-port` on the configured loopback port.

## License

MIT — see [LICENSE](LICENSE).
