# aIRC

Chat with an AI from the IRC client you already use.

aIRC is a small IRC server for that and nothing else. You connect over TLS with SASL. Each AI is a nick that stays online. Each conversation is a private channel with you and that nick.

An admin adds the models and the API keys from inside IRC. Everyone else can talk. Keys stay on the server.

## Start the server

You need Go 1.27.

```sh
git clone https://github.com/theesfeld/airc.git
cd airc
go build -o airc ./cmd/airc
./airc -name irc.example.com
```

The first run creates `airc.yaml`, a database, a self-signed certificate, and an `admin` account. The password is printed once and is not saved:

```text
aIRC initialized
  config: airc.yaml
  admin account: admin
  admin password: <shown once>
aIRC listening on [::]:6697 as irc.example.com
TLS certificate SHA-256: AA:BB:...
```

Copy the password and the fingerprint somewhere safe. The next start reuses the same files. `-name` and `-listen` are read only while `airc.yaml` is being created. After that, edit the file. `airc.example.yaml` shows every setting.

Lost the admin password:

```sh
./airc reset-password admin
```

### Docker

```sh
docker build -t airc .
mkdir -p airc-data
sudo chown 65532:65532 airc-data
docker run --rm -p 6697:6697 -v "$PWD/airc-data:/data" airc
```

The admin password is in the container output. The data directory has to be writable by uid 65532. The image can call HTTPS model APIs.

### systemd

```sh
sudo useradd --system --create-home --home-dir /var/lib/airc airc
sudo install -m 0755 airc /usr/local/bin/airc
sudo install -d -o airc -g airc -m 0700 /var/lib/airc
sudo cp distrib/airc.service /etc/systemd/system/airc.service
sudo systemctl enable --now airc
sudo journalctl -u airc -e
```

The first start prints the admin password in the journal.

## Connect

There is no plaintext port and no public registration. An admin creates every account. Your account name is your nick, and it does not change.

Use SASL `SCRAM-SHA-256` when the client offers it. `PLAIN` also works. A server password (`PASS`) is ignored.

The certificate on a fresh install is self-signed. Check that your client sees the SHA-256 fingerprint aIRC printed at startup before you send the password.

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

### irssi

```text
/NETWORK ADD -sasl_mechanism SCRAM-SHA-256 -sasl_username admin -sasl_password <password> airc
/SERVER ADD -network airc -tls -tls_verify no -port 6697 irc.example.com
/CONNECT -tls_pinned_cert <fingerprint> airc
```

### HexChat

Add a network, turn SSL on, and set SASL to SCRAM-SHA-256 (or PLAIN) with your account name and password. For the generated certificate, turn verification off and compare the fingerprint HexChat shows with the one from the server log.

When you have a real certificate, replace `data/tls/cert.pem` and `data/tls/key.pem`, then restart. aIRC leaves an existing pair in place.

## Talk

Your IRC client keeps slash commands for itself. Message the `airc` nick, or send a server command with `/quote`.

```text
/msg airc help
/quote AIRC help
```

Message an AI nick to open a conversation, or to continue the latest one:

```text
/msg helper what is a private channel?
```

aIRC joins you to a channel such as `#helper-1a2b3c4d`. That channel is the transcript. Only you can see it or join it. Say the next line in the channel, or keep messaging the nick.

```text
/msg airc session list
/msg airc session new helper
/msg airc session close #helper-1a2b3c4d
/msg airc passwd <new-password>
```

`session new` opens another channel with the same AI. Leaving the channel keeps the session. The next time you connect, aIRC joins you again and shows the recent lines.

`/me` is delivered as the action text. Version, ping, and time CTCP queries get an answer from the server and are not sent to the model.

## Add a model

Do this from the admin account. The key is stored encrypted. `ai list` prints `key=set` and never the key itself.

xAI, including `grok-build-0.1`:

```text
/msg airc ai add helper grok grok-build-0.1 <xai-api-key>
```

That uses `https://api.x.ai/v1`. You choose the model name.

Any OpenAI-compatible chat endpoint (OpenAI, OpenRouter, Ollama, vLLM, and others):

```text
/msg airc ai add helper openai grok-build-0.1 https://api.example.com/v1 <api-key>
```

The server sends `POST {base}/chat/completions` with a bearer token. For a program on the same machine, an `http://` URL is accepted for `localhost` and for a literal private address such as `http://127.0.0.1:11434/v1`. Public endpoints need `https://`.

```text
/msg airc ai list
/msg airc ai edit helper model grok-4.7
/msg airc ai edit helper url https://api.example.com/v1
/msg airc ai edit helper key <new-key>
/msg airc ai rm helper
```

Removing an AI closes its sessions.

## Add people

Passwords you set need at least 12 characters. Names are 1–32 characters: a letter, then letters, digits, `_`, or `-`. `airc`, `nickserv`, and `chanserv` are reserved.

```text
/msg airc user add alice <password>
/msg airc user list
/msg airc user passwd alice <password>
/msg airc user role alice admin
/msg airc user rm alice
```

Members can chat and change their own password. They cannot add models or read keys. The last admin cannot be removed or demoted, and you cannot remove the account you are logged in as.

## Settings

`airc.yaml` holds the server name, listen address, data directory, and limits. Account passwords and API keys are not in that file.

| Setting | Default | What it changes |
| --- | --- | --- |
| `server.listen` | `:6697` | TLS address |
| `limits.replay` | `100` | Lines shown again when you rejoin |
| `limits.context_messages` | `40` | Lines sent to the model |
| `limits.provider_timeout` | `180s` | How long a reply may take |
| `limits.auth_failures` | `5` | Failures from one address before a ban |
| `limits.auth_ban` | `10m` | How long that ban lasts |
| `limits.max_connections` | `1000` | Open connections |

Provider keys live in the database, sealed with `data/secret.key`. Keep that file with the database. If you lose it, the stored API keys cannot be opened. Passwords are separate and can be reset with `airc reset-password`.

## Good to know

- Login is SASL over TLS. A connection that never authenticates is closed.
- A wrong password and an unknown account look the same to the client.
- Three bad SASL attempts on one connection close it. Repeated failures from one address are banned in memory for the ban duration.
- Logs record who connected and, on a failed login, the address. They do not record chat text, passwords, or API keys.
- If your client has echo-message on, your own `ai add` line comes back to you, including the key you typed. It is not sent to anyone else.
- A session channel does not appear in other people's channel lists. Joining someone else's session is refused.
- There is no server linking, DCC, operator console, or ident. Clients that only need registration, private messages, and channels work.
- Replies are split into short lines. Line breaks from the model stay as separate messages.

## Development

```sh
make test
make build
```

## License

MIT. Copyright 2026 theesfeld.
