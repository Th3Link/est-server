# est-server

An EST ([RFC 7030](https://www.rfc-editor.org/rfc/rfc7030)) server for small
clients that need a TLS server certificate, such as the homeautomation
gateways. It runs either

- **standalone**, signing with a CA of its own (one binary, systemd or
  container), or
- **in Kubernetes**, in front of **cert-manager**: every enrollment becomes
  a `CertificateRequest`, so any issuer works (a CA issuer, Vault, ACME).

It implements `simpleenroll`, `simplereenroll` and `cacerts`. It does not
implement `csrattrs`, `serverkeygen` or `fullcmc`.

## Who gets a certificate

Clients authenticate only with TLS client certificates. There is no HTTP
authentication. Per endpoint ("label"):

| Request | Approved when |
|---|---|
| `simpleenroll` | the client presents a certificate from a configured **device identity CA** that names the requested host, **or** every requested name matches the **allowlist** (`*.home.example.com`), **or** an administrator approves it (`202` + `Retry-After` until then; needs `manual_approval = true`) |
| `simplereenroll` | the client presents its current certificate from this label's CA, for the same names. The key may stay the same |

The issued certificates carry the requested DNS names as SAN, `digitalSignature`
and the EKUs `serverAuth` and `clientAuth`. The `clientAuth` EKU is there so
the client can authenticate its renewal with the certificate.

## Quick start (standalone)

```sh
cargo build --release
./target/release/est-server init --dir /var/lib/est-server \
    --dns-name est.home.example.com --allow '*.home.example.com'
./target/release/est-server -c /var/lib/est-server/est-server.toml serve
```

`init` creates a root CA, the server certificate (renewed automatically) and a
configuration. Install `ca/ca.crt` on the clients as trust anchor. Requests
outside the allowlist wait for an administrator:

```sh
est-server -c /var/lib/est-server/est-server.toml pending list
est-server -c /var/lib/est-server/est-server.toml pending approve 9737
```

More in [docs/standalone.md](docs/standalone.md). For Kubernetes, see
[docs/kubernetes.md](docs/kubernetes.md). What clients must do is in
[docs/clients.md](docs/clients.md).

## Network

- Dual-stack: `[::]:8443` serves IPv6 and IPv4 on one socket. Logs, pending
  requests and the issue log show IPv4 clients as plain IPv4 addresses.
- TLS 1.2 and 1.3, AES-GCM with ECDHE only (no ChaCha20, no CBC, no static
  RSA). Groups: x25519, P-256, P-384.
- A client certificate is requested but not required. A certificate from an
  unknown CA does not break the handshake. The request is then treated as
  anonymous.
- `/healthz` and `/readyz` are served over plain HTTP on a separate port
  (`[::]:8080`).

## Layout

| Path | Content |
|---|---|
| `crates/est-proto` | wire format: base64 bodies, PKCS#10 parsing and checks, certs-only PKCS#7. The CMS code is derived from [est-ca](https://crates.io/crates/est-ca) 0.2.0 (see its NOTICE) |
| `crates/est-server` | the server: TLS, policy, local CA, cert-manager signer, pending store, CLI |
| `deploy/helm/est-server` | Helm chart (cert-manager) |
| `deploy/systemd` | systemd unit and sysusers file |
| `Dockerfile` | static musl binary in a distroless image |
| `tests/e2e/kind.sh` | end-to-end test with cert-manager in a dual-stack kind cluster |

## Tests

```sh
cargo test                 # unit tests + gateway-like integration tests (IPv4 and IPv6)
tests/e2e/kind.sh          # cert-manager end to end (needs docker, kind, helm, cmctl)
```

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option. `est-proto` contains code
derived from [est-ca](https://crates.io/crates/est-ca), see
[its NOTICE](crates/est-proto/NOTICE).
