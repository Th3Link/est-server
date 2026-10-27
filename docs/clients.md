# What clients have to do

This is the server side of
`homeautomation-unified/software/gateway-core/docs/est-server.md`, checked
against that list:

| Gateway requirement | est-server |
|---|---|
| IPv4, DNS name in the server certificate | listens dual-stack; `server.tls.auto` / the chart's `serverCertificate` put DNS names (and IPs) into the SAN |
| TLS 1.2/1.3, AES-GCM, ECDHE, x25519/P-256/P-384 | exactly these suites and groups |
| ECDSA server certificate, SHA-256/384 | `init` and the chart use ECDSA P-256 |
| Chain ≤ 16 KiB | leaf + intermediates only |
| `simpleenroll`/`simplereenroll`, base64 PKCS#10 | yes (also raw DER) |
| Answer: base64 certs-only PKCS#7 | yes, 64-character lines |
| Authentication only by TLS client certificate | device identity CAs (`identity_cas`), renewal with the current certificate |
| First enrollment without identity | allowlist or approval (`202`, numeric `Retry-After`) |
| Renewal keeps the key | allowed |
| No `tls-unique` in the CSR | not required |
| SAN DNS name, `serverAuth`, `digitalSignature` | always |
| ≤ 5 certificates, ≤ 6 KiB chain, ≤ 12 KiB answer | logged as a warning if exceeded (a leaf from a root CA is ~0.7 KiB) |
| `notBefore` ≤ 5 min in the future | backdated by 5 min |

For any client:

1. Make a key and a CSR with the host name as SAN DNS name (and/or CN).
   Only DNS names are issued. IP addresses, e-mail addresses and the like
   are refused.
2. `POST /.well-known/est[/<label>]/simpleenroll` with
   `Content-Type: application/pkcs10` and a base64 body.
3. On `202`, wait `Retry-After` seconds and send again. A new CSR for the
   same key and names counts as the same request.
4. Renew with `simplereenroll`, presenting the current certificate and
   key as TLS client certificate, for the same names.

With curl and openssl:

```sh
openssl ecparam -name prime256v1 -genkey -noout -out dev.key
openssl req -new -key dev.key -subj /CN=box1.home.example.com \
  -addext subjectAltName=DNS:box1.home.example.com -outform DER | base64 -w64 > dev.csr
curl --cacert ca.crt -H 'Content-Type: application/pkcs10' --data-binary @dev.csr \
  https://est.home.example.com:8443/.well-known/est/simpleenroll | base64 -d \
  | openssl pkcs7 -inform DER -print_certs > dev.crt
curl --cacert ca.crt --cert dev.crt --key dev.key -H 'Content-Type: application/pkcs10' \
  --data-binary @dev.csr https://est.home.example.com:8443/.well-known/est/simplereenroll | …
```
