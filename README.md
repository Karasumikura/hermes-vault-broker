# hermes-vault-broker

**An out-of-process credential broker for Hermes Agent: the agent asks, the broker fills, the key never enters the agent's domain.**

Hermes can already save a login and fill it. That keeps the password out of the model's transcript — but the key that decrypts the vault still sits next to its ciphertext, inside the same trust domain as the agent that also runs `terminal`. This plugin removes that: the credentials live behind a socket, in a process that runs as its own user, holds the key only in locked memory, and performs the page write itself.

---

## Why the key belongs in its own trust domain

Encryption protects a stored file, not a running agent. In the default layout the ciphertext and its key share one directory, so a single prompt injection that reaches the `terminal` tool owns the whole vault:

```
$ cat ~/.hermes/vault/vault.key
$ python -c "...Fernet(key).decrypt(open('vault.json.enc','rb').read())"
decrypted: 1 item (label=kaggle, password=8 chars)
```

This plugin removes the key from that reach. The data key is derived from a passphrase with scrypt at boot and lives only in mlock'd memory inside the broker process; the disk holds a wrapped key and ciphertext, nothing more. No backup, sync folder, swap file or log can yield it.

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
   AF_UNIX /run/hermes-vault-broker/sock        ← SO_PEERCRED: gateway uid + broker uid only
        │
        ▼
   hermes-vault-broker   (User=vaultd, ProtectHome=yes, ProtectSystem=strict)
        │   KEK = scrypt(passphrase)   →  DEK in mlock'd memory
        │   origin must equal the item's bound origin, exactly
        ▼
   Chrome DevTools Protocol (127.0.0.1:9223)
        └─ the broker writes the field and submits, returns {filled, submitted}
```

The agent's tool result is a count. There is no code path that returns the password.

### Wire format

One JSON object per line, one request per connection:

| op | request | reply |
|---|---|---|
| `status` | — | `{"ok", "unlocked", "items"}` |
| `unlock` | `passphrase` | `{"ok"}` |
| `lock` | — | `{"ok"}` |
| `list` | — | `{"ok", "items": [{handle, label, origin, identifier, ...}]}` |
| `add` | `label, origin, identifier_type, identifier, password` | `{"ok", "handle"}` |
| `remove` | `handle` | `{"ok", "removed"}` |
| `fill` | `handle, origin, cdp?, submit?` | `{"ok", "filled", "submitted"}` |

Identifiers are metadata, not secrets: the agent may read them and type them. Only the password is sealed.

---

## Install

```bash
git clone https://github.com/Karasumikura/hermes-vault-broker
cd hermes-vault-broker
sudo ./scripts/install.sh
```

That creates the `vaultd` system user, installs the tree to `/opt/hermes-vault-broker` with its own venv, generates a self-signed certificate for the unlock page, and enables `hermes-vault-broker.service`.

Then:

```bash
# 1. create the store — asks twice, stores neither the passphrase nor a key derived from it
sudo -u vaultd /opt/hermes-vault-broker/venv/bin/python -m broker --state /var/lib/hermes-vault-broker/store.json init

# 2. unlock it for this session: a one-time HTTPS page, works on a phone
sudo -u vaultd /opt/hermes-vault-broker/venv/bin/python -m broker unlock-form \
  --cert /var/lib/hermes-vault-broker/tls/server.crt \
  --key  /var/lib/hermes-vault-broker/tls/server.key \
  --port 58104 --public-url https://<host>:58104

# 3. add a login (reads the password from the terminal, never from argv)
sudo -u vaultd /opt/hermes-vault-broker/venv/bin/python -m broker add \
  --label kaggle --origin https://www.kaggle.com --identifier you@example.com
```

Import existing Hermes vault items:

```bash
sudo -u vaultd /opt/hermes-vault-broker/venv/bin/python -m broker migrate \
  --key ~/.hermes/vault/vault.key --enc ~/.hermes/vault/vault.json.enc
```

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

If the socket is unreachable the tool says so; if the page is on another origin, the broker refuses and writes nothing.

---

## What you get

- **Zero key material on disk.** Passphrase → scrypt → KEK → wrapped DEK; the plaintext key exists only in the broker's memory.
- **The agent never holds a password.** Socket in `(handle, origin)`, count out.
- **A real boundary between processes.** `vaultd` runs with `ProtectHome=yes` and `ProtectSystem=strict`; it cannot read the agent's home.
- **Exact-origin binding, re-asserted in the page.** The origin is checked on the way in and again inside the tab immediately before the write, so a navigation between check and fill writes nothing.
- **Peer-credential check.** The socket answers only the gateway's uid and the broker's own.
- **One broker for every profile.** No more per-profile vault copies, no re-adding the same login per profile.
- **A short dependency list.** `cryptography` and `websockets`, nothing else.

---

## Design notes

**Crypto.** AES-256-GCM in two layers: the data key is wrapped by a passphrase-derived key, and the item body is encrypted with the data key. Both nonces are stored; neither key is. KDF parameters live in the file so the cost can be raised later without invalidating a store.

**Memory.** `LimitMEMLOCK=infinity` in the unit plus `mlock` keeps the key out of swap — on a box that swaps, an unlocked page is a key on disk.

**Unlock.** The broker starts locked and stays locked until someone types the passphrase into the one-time page. That page carries a single-use random token, disables request logging (the URL carries the token), sends `no-store`, and exits after one successful submission. Wrong passphrases hit a brake: five failures pause `unlock` for a minute.

**Fill.** The broker lists DevTools targets, picks the tab whose origin matches the item, and evaluates one self-contained script that re-checks `window.location.origin`, writes through the native `HTMLInputElement` value setter (so React-controlled inputs see it), dispatches `input` and `change`, and optionally calls `requestSubmit()`. The reply is a count.

**Failure modes are loud.** A missing socket, a locked store, a wrong origin, or a missing tab each return a distinct error the agent can act on. None of them silently skip the fill.

---

## Development

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
```

31 tests, stdlib `unittest` only: crypto round-trips, wrong passphrase, lock semantics, on-disk plaintext absence, origin refusal, peer-uid rejection, unlock brake, the CDP tab lookup against a fake DevTools endpoint, and a real AF_UNIX round trip.

## Compatibility

Linux. The broker needs `AF_UNIX`, `SO_PEERCRED` and systemd user/state directories; the CDP client needs a browser started with `--remote-debugging-port=9223`.

## License

MIT — see [LICENSE](LICENSE).
