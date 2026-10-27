# Kubernetes with cert-manager

The server turns every EST request into a cert-manager
`CertificateRequest` in its namespace and waits for it (up to `wait`,
default 20 s). If the certificate isn't ready by then, it answers `202`.
The client asks again and gets the same request back, because the request
is named after label, names and public key.

## Install

```sh
helm install est deploy/helm/est-server -n est --create-namespace \
  --set 'serverCertificate.dnsNames[0]=est.home.example.com' \
  --set image.repository=<registry>/est-server
```

By default the chart creates:

- a self-signed bootstrap CA (`Issuer est-est-server-ca`, secret
  `est-est-server-ca`). It signs both the server certificate and the
  client certificates. Clients get its `ca.crt` as trust anchor (see the
  install notes);
- the server certificate (`Certificate est-est-server-tls`), which the
  server reloads when cert-manager renews it;
- a `LoadBalancer` service, `PreferDualStack`, port 443 → 8443. EST needs
  TLS up to the pod for client certificates, so an Ingress only works
  with TLS passthrough;
- RBAC to create, read and delete `CertificateRequests` and to approve
  them for issuers (`signers` / `approve`).

The server configuration is the `config` value (TOML, rendered with `tpl`).

## Approval

| Policy outcome | What the server does with the CertificateRequest |
|---|---|
| renewal, device identity, allowlist | creates it and sets `Approved` itself |
| needs approval | creates it and leaves it unapproved: `cmctl approve -n est <name>` or approver-policy decides |

**cert-manager's built-in approver approves every request.** For manual
approval to mean anything, turn it off:

```sh
helm upgrade cert-manager jetstack/cert-manager -n cert-manager --reuse-values \
  --set 'extraArgs={--controllers=*\,-certificaterequests-approver}'
```

Then approve with `cmctl` or install
[approver-policy](https://cert-manager.io/docs/policy/approval/approver-policy/).
Remember that the server's own `Certificate` needs approval then as well.
If the built-in approver approves a request that needed manual approval,
est-server does not hand out the certificate. It logs an error instead.

Waiting requests:

```sh
kubectl -n est get certificaterequests -l app.kubernetes.io/managed-by=est-server
kubectl -n est get certificaterequest est-1a2b3c... -o jsonpath='{.metadata.annotations}'   # names, client address
cmctl approve -n est est-1a2b3c...
```

Finished requests are deleted after `keep` (default 24 h). Unfinished
ones are deleted after 7 days.

## Other issuers

```toml
[[label]]
signer = { type = "cert-manager", issuer = { name = "letsencrypt-dns", kind = "ClusterIssuer" }, cacerts = "/etc/est-server/ca/ca.crt", duration = "2160h", wait = "20s" }
allow = ["*.home.example.com"]
```

- `cacerts` holds the issuer's CA certificates (served at `/cacerts`, and
  trusted for renewals). Mount them via `caSecret` or `extraVolumes`.
- **ACME / Let's Encrypt (DNS-01)** works, which gives browser-trusted
  certificates. Issuing takes longer than `wait`, so clients get a `202`
  first. The names must be public DNS names in your zone. Let's Encrypt
  no longer issues `clientAuth` certificates. That is fine, because
  renewals are also accepted with a `serverAuth`-only certificate.
- Several labels can use different issuers, e.g. `/.well-known/est` for
  the CA and `/.well-known/est/public` for ACME.

## Local CA in the cluster

`signer = { type = "local", … }` works in the cluster too. Mount the CA
key from a secret via `extraVolumes`. With `manual_approval`, turn on
`persistence` for the pending store, run one replica, and approve with
`kubectl exec deploy/est-est-server -- est-server -c /etc/est-server/config/est-server.toml pending approve <id>`.

## Server outside the cluster

The server doesn't have to run in the cluster it sends its requests to.
Without further configuration it uses the in-cluster service account, or
`$KUBECONFIG` / `~/.kube/config`. To pin it:

```toml
[kubernetes]
kubeconfig = "/etc/est-server/kubeconfig"   # relative to the config file
context = "home"                            # optional
```

The end-to-end tests run the server this way, against a kind cluster.
