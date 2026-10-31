# Standalone operation

## Install

```sh
cargo build --release
sudo install -m 0755 target/release/est-server /usr/local/bin/
sudo install -m 0644 deploy/systemd/est-server.sysusers /usr/lib/sysusers.d/est-server.conf
sudo systemd-sysusers
sudo install -m 0644 deploy/systemd/est-server.service /etc/systemd/system/
sudo install -d -o est-server -g est-server -m 0700 /var/lib/est-server
sudo -u est-server est-server init --dir /var/lib/est-server \
    --dns-name est.home.example.com --ip 192.0.2.10 --ip 2001:db8::10 \
    --allow '*.home.example.com'
sudo systemctl enable --now est-server
```

`init` writes:

| File | |
|---|---|
| `est-server.toml` | the configuration, with paths relative to the file |
| `ca/ca.crt` | the root CA: install it on clients as trust anchor |
| `ca/ca.key` | its key (mode 0600). Back it up |
| `tls/tls.crt`, `tls/tls.key` | the server certificate, renewed by the server when a third of its lifetime is left (`server.tls.auto`) |

The unit runs as user `est-server` with `CAP_NET_BIND_SERVICE`, so
`listen = ["[::]:443"]` works too. Clients use port 443 unless the URL
names another.

As a container:

```sh
docker build -t est-server .
docker run -d -p 8443:8443 -v /srv/est:/var/lib/est-server \
  -e EST_SERVER_CONFIG=/var/lib/est-server/est-server.toml est-server
```

The image runs as uid 65532: `chown -R 65532:65532 /srv/est`.

## Approval

Requests that neither the allowlist nor a device identity approves wait
in `<state_dir>/pending/` if `manual_approval = true`:

```sh
est-server pending list          # waiting requests (--all: decided ones too)
est-server pending show <id>     # with the CSR
est-server pending approve <id>  # a unique prefix of the id is enough
est-server pending deny <id>
```

The client gets the certificate the next time it asks (after
`Retry-After`). An approval covers one key and one set of names and stays
good for 7 days. Requests untouched for 30 days are deleted.

## Registered clients

Register clients with their names and the pin of their public key, one
TOML file per client in a directory:

```toml
# clients.d/gw1.toml
dns_names = ["gw1.example.com"]
public_keys = [{ pin_sha256 = "n+ySAtnNUmtp0GQTO6oZUJn+dFSHlAfPhBunhhOkG9Q=" }]
labels = []                       # optional: only these EST labels
```

```toml
# est-server.toml
[clients]
dir = "clients.d"                 # re-read every reload (default 30s)

[[label]]
signer = { type = "local", ca = "local" }
registered = "required"           # or "optional"
```

`est-server pin <csr|certificate|key>` prints the pin. With `required`,
only registered keys get certificates, only for their names, and a
renewal must present a certificate with a key of the same client.
`optional` approves registered keys and handles the rest as usual.
Invalid files are logged and ignored.

## Configuration reference

```toml
[server]
listen = ["[::]:8443"]            # several addresses possible; with 0.0.0.0:P and [::]:P each family gets a socket
health_listen = ["[::]:8080"]     # [] turns health off
state_dir = "."

[server.tls]
cert = "tls/tls.crt"              # re-read every 30 s when it changes
key = "tls/tls.key"
auto = { ca = "local", dns_names = ["est.example.com"], ip_addresses = ["192.0.2.10", "2001:db8::10"], validity = "90d" }

[[ca]]
name = "local"
cert = "ca/ca.crt"                # the signing CA (root or intermediate)
key = "ca/ca.key"
chain = "ca/chain.pem"            # optional: certificates above it

[clients]                         # optional: registered clients
dir = "clients.d"
# kubernetes = { namespace = "est" }   # EstClient objects

[[label]]                         # name = "" -> /.well-known/est
name = ""
# path = "/est/gateways"          # optional: a path of its own
signer = { type = "local", ca = "local", validity = "90d" }
allow = ["*.home.example.com"]    # *. one label, **. any depth, or exact names
identity_cas = ["identity-ca.pem"]
identity_name_match = true        # the identity must name the requested hosts
manual_approval = true
retry_after = "2m"
include_root = false              # send the root CA along
registered = "off"                # off | optional | required, see "Registered clients"

[[label]]                         # -> /.well-known/est/servers
name = "servers"
signer = { type = "local", ca = "local", validity = "30d" }
```

Every issued certificate is logged to `<state_dir>/issued.jsonl`.

To sign with an intermediate CA, point `[[ca]]` at it and put the root
into `chain`. Answers then contain the intermediate, and the root only
with `include_root`.
