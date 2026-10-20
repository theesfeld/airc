# aIRC

aIRC is an IRC server that does one thing: private chat with an AI.

Any IRC client can connect. The listener is TLS on port 6697. SASL is required before the connection is registered. An AI is a nick that is always present. A session is a private channel that contains only you and that nick.

It is a single static binary. The first run creates the config, a self-signed certificate, an encryption key, and an `admin` account. The admin password is printed once.

## Why a new server

aIRC is not a plugin for an existing ircd.

A general server is built around linking, operators, services, and open channels. None of those are this product. SASL has to be the only way in, with no PASS-only or anonymous path. An AI nick needs an encrypted provider key and a private session that other users cannot see or join. `RELAYMSG` cannot give a private message its own identity. InspIRCd still hands SASL to a separate services daemon. Ergo can require SASL and disable registration, and it has no plugin API that can limit the server to these chats.

The binary speaks the client protocol: the commands clients send from RFC 1459 and RFC 2812, plus the IRCv3 capabilities listed below. It does not speak server-to-server (RFC 2813).

## Run

Requires Go 1.27.

```sh
go build -o airc ./cmd/airc
./airc
```

`./airc` with no arguments creates `airc.yaml` in the working directory when that file is missing, then listens. Relative paths in the config are resolved from the config file's directory.

```text
aIRC initialized
  config: airc.yaml
  admin account: admin
  admin password: <shown once>
aIRC listening on [::]:6697 as irc.localhost
TLS certificate SHA-256: AA:BB:...
```

Store the password somewhere else. It is not written to disk. If you lose it:

```sh
./airc reset-password admin
```

Other commands: `airc init`, `airc run -config airc.yaml`, `airc version`. `-name` and `-listen` apply only while the config file is being created. After that, edit `airc.yaml`.

`airc.example.yaml` is the same text the first run writes, with a sample server name.

### Real certificate

The first run writes a self-signed ECDSA certificate at `data/tls/cert.pem` and `data/tls/key.pem`. Replace both files and restart. aIRC will not overwrite a pair that is already there. Do not advertise SASL STS while the certificate is self-signed.

Clients should check the SHA-256 fingerprint printed at startup before they trust the generated certificate.

### systemd

`distrib/airc.service` runs the binary as user `airc` with a state directory:

```sh
sudo useradd --system --create-home --home-dir /var/lib/airc airc
sudo install -m 0755 airc /usr/local/bin/airc
sudo install -d -o airc -g airc -m 0700 /var/lib/airc
sudo cp distrib/airc.service /etc/systemd/system/airc.service
sudo systemctl enable --now airc
sudo journalctl -u airc -e
```

The first start prints the admin password in the journal. Port 6697 does not need extra capabilities.

### Docker

The image is a static binary on `gcr.io/distroless/static-debian12:nonroot` (uid 65532). The CA bundle from the build image is copied in, because that base image does not include one and provider HTTPS would fail without it.

```sh
docker build -t airc .
mkdir -p airc-data
sudo chown 65532:65532 airc-data
docker run --rm -p 6697:6697 -v "$PWD/airc-data:/data" airc
```

The admin password is in that process's stdout. The volume has to be writable by uid 65532.

## Connect

The account name is the nick. You cannot change nicks. There is no plaintext port and no registration from the client. An admin creates every account.

SASL mechanisms: `PLAIN` and `SCRAM-SHA-256`. Prefer SCRAM. `PASS` is accepted during registration and ignored. It is not a login.

### WeeChat

```text
/server add airc irc.example.com/6697
/set irc.server.airc.sasl_mechanism scram-sha-256
/set irc.server.airc.sasl_username admin
/set irc.server.airc.sasl_password <password>
/set irc.server.airc.tls_verify off
/set irc.server.airc.tls_fingerprint <64 hex digits, colons removed>
/connect airc
```

`tls_fingerprint` pins the certificate aIRC printed at startup.

### irssi

```text
/NETWORK ADD -sasl_mechanism SCRAM-SHA-256 -sasl_username admin -sasl_password <password> airc
/SERVER ADD -network airc -tls -tls_verify no -port 6697 irc.example.com
/CONNECT -tls_pinned_cert <fingerprint> airc
```

### HexChat

Add a network, enable SSL, and set the SASL mechanism to SCRAM-SHA-256 (or PLAIN) with the account name and password. For the generated certificate, turn certificate verification off and compare the fingerprint HexChat shows with the one aIRC printed.

## Chat

IRC clients treat an unknown `/` command as their own command. Talk to the server by messaging the `airc` nick, or send the server command with `/quote`:

```text
/msg airc help
/quote AIRC help
```

Messaging an AI nick continues your latest open session with that nick, or opens one:

```text
/msg helper what is a private channel?
```

The server joins you to `#helper-<8 hex>`. That channel is the conversation. `+i` keeps everyone else out. Your modes on it are `+isnt`, and you are `+o`. Leaving the channel does not delete the session. The next login joins it again and replays recent messages.

```text
/msg airc session new helper
/msg airc session list
/msg airc session close #helper-1a2b3c4d
/msg airc passwd <new-password>
```

`session new` always opens another channel, including when one is already open. `PART` only leaves the buffer.

CTCP `VERSION`, `PING`, and `TIME` are answered by the server and are not sent to the model. A CTCP `ACTION` is sent as its text.

## Accounts and models

Admins manage AI nicks and provider keys in band. Other users can chat. They cannot list or change keys. `ai list` shows `key=set` and never the key.

```text
/msg airc ai add helper openai grok-build-0.1 https://api.example.com/v1 sk-...
/msg airc ai add helper grok grok-build-0.1 xai-...
/msg airc ai edit helper model grok-4.7
/msg airc ai edit helper url https://api.example.com/v1
/msg airc ai edit helper key xai-...
/msg airc ai rm helper
/msg airc user add alice <password of at least 12 characters>
/msg airc user list
/msg airc user passwd alice <password>
/msg airc user role alice admin
/msg airc user rm alice
```

`grok` is the OpenAI-compatible xAI API at `https://api.x.ai/v1`. The model id is whatever the admin sets. `grok-build-0.1` is the one these examples use. `openai` is any server that accepts `POST {base}/chat/completions` with `Authorization: Bearer` and `{"model","messages","stream":false}`. That covers OpenAI, OpenRouter, Ollama, and vLLM. Give `openai` an explicit base URL.

HTTP base URLs are allowed only for `localhost` and literal private or loopback addresses, so a local model works. HTTPS is allowed for public hosts. Redirects are not followed. The dialer refuses link-local and metadata addresses.

Keys are sealed with AES-256-GCM under `data/secret.key` before they are stored. The YAML file has no secrets. Keep `secret.key`. Without it, stored provider keys cannot be opened. Passwords are not under that key. They are stored as SCRAM-SHA-256 (PBKDF2-HMAC-SHA256, 600000 iterations by default).

The last admin cannot be removed or demoted. An admin cannot remove the account they are using.

Nick names match `^[A-Za-z][A-Za-z0-9_\-]{0,31}$`. `airc`, `nickserv`, and `chanserv` are reserved.

## What the server speaks

Advertised when the client asks with `CAP LS 302`:

| Capability | Behavior |
| --- | --- |
| `sasl=PLAIN,SCRAM-SHA-256` | Required. The value is sent only for CAP version 302. |
| `message-tags`, `server-time`, `account-tag` | Tags on chat lines when the client enabled them. |
| `echo-message` | The server sends your own message back to you. |
| `batch` | History replay on join uses `batch` type `chathistory` when `message-tags` is also on. |
| `labeled-response` | A label on a command is copied onto the replies for that command. |
| `account-notify`, `away-notify`, `extended-join`, `multi-prefix`, `cap-notify` | Advertised. Caps are fixed once registration finishes. |

History is the join replay of the last `replay` messages (default 100). There is no `CHATHISTORY` command. The model sees the last `context_messages` lines (default 40). Replies are split into short UTF-8 lines. Bytes that would break a line (`CR`, `LF`, `NUL`) are removed from each line, so model text cannot become a new IRC command.

Intentionally absent:

- server-to-server linking
- ident
- an operator console
- DCC relay
- open registration
- a plaintext listener

`ISUPPORT` includes `CASEMAPPING=ascii`, `CHANTYPES=#`, `PREFIX=(o)@`, `NETWORK=aIRC`, and `UTF8ONLY`.

## Security

- TLS 1.2 or newer is the only listener. The generated certificate is self-signed. Pin its fingerprint, or replace it.
- `NICK` and `USER` without SASL, `PASS` alone, and `CAP END` before SASL all close the connection.
- A bad password and an unknown account fail the same way. Unknown names still run the password derivation. The fake salt is a MAC of the on-disk key, so it stays stable across restarts.
- Three SASL failures on one connection, or `auth_failures` (default 5) from one address, ban that address for `auth_ban` (default 10 minutes). The ban is in memory.
- `data/` is mode `0700`. The database and `secret.key` are mode `0600`.
- Logs record account names and, on auth failure, the client address. They do not record message bodies, `AUTHENTICATE` lines, passwords, or provider keys.
- With `echo-message` enabled, the server sends your own `ai add` line back to your client. That line contains the key you just typed. It is not sent to anyone else.
- Each session channel is visible only to its owner. `LIST`, `WHO`, `WHOIS`, and `NAMES` follow that rule. A join by anyone else gets `473`.
- Provider calls use a 180 second timeout by default. Response bodies are capped at 2 MiB. Errors shown to users contain the status code, not the upstream body.

## Development

```sh
make test
make build
```

Tests use a temporary directory and do not create `./airc.yaml` or `./data` in the tree. `CGO_ENABLED=0` is enough. SQLite is `modernc.org/sqlite`.

GitHub Actions runs `go test ./...` on push and pull request.

## License

MIT. Copyright 2026 theesfeld.
