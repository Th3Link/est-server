#!/usr/bin/env bash
# End-to-end test against cert-manager in a dual-stack kind cluster.
# Needs: docker, kind, kubectl, helm, cmctl, openssl, curl.
#
#   tests/e2e/kind.sh            # create cluster, test, delete cluster
#   KEEP=1 tests/e2e/kind.sh     # leave the cluster running
set -euo pipefail

CLUSTER=est-e2e
NS=est
REL=est
HOST=est.e2e.test
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=$(mktemp -d)
trap '[[ -n "${KEEP:-}" ]] || kind delete cluster --name $CLUSTER; rm -rf "$WORK"' EXIT

cat > "$WORK/kind.yaml" <<YAML
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  ipFamily: dual
YAML
kind create cluster --name $CLUSTER --config "$WORK/kind.yaml"

docker build -t est-server:e2e "$ROOT"
kind load docker-image est-server:e2e --name $CLUSTER

# cert-manager without its built-in approver, so manual approval is real.
helm repo add jetstack https://charts.jetstack.io --force-update >/dev/null
helm install cert-manager jetstack/cert-manager -n cert-manager --create-namespace --wait \
  --set crds.enabled=true \
  --set 'extraArgs[0]=--controllers=*\,-certificaterequests-approver'

helm install $REL "$ROOT/deploy/helm/est-server" -n $NS --create-namespace \
  --set image.tag=e2e --set service.type=ClusterIP \
  --set "serverCertificate.dnsNames[0]=$HOST" \
  --set 'config=[server]
state_dir = "/var/lib/est-server"
[server.tls]
cert = "/etc/est-server/tls/tls.crt"
key = "/etc/est-server/tls/tls.key"
[[label]]
signer = { type = "cert-manager", issuer = { name = "est-est-server-ca", kind = "Issuer" }, cacerts = "/etc/est-server/ca/ca.crt" }
allow = ["*.auto.e2e.test"]
manual_approval = true
retry_after = "60s"'
# The server certificate is approved by hand too (no built-in approver).
for i in $(seq 60); do
  kubectl -n $NS get certificaterequest -o name | grep -q . && break; sleep 2
done
for cr in $(kubectl -n $NS get certificaterequest -o name); do cmctl approve -n $NS "${cr#*/}" || true; done
kubectl -n $NS rollout status deploy/$REL-est-server --timeout=180s

kubectl -n $NS get secret $REL-est-server-ca -o jsonpath='{.data.ca\.crt}' | base64 -d > "$WORK/ca.crt"
kubectl -n $NS port-forward svc/$REL-est-server 18443:443 >/dev/null 2>&1 &
PF=$!
trap 'kill $PF 2>/dev/null; [[ -n "${KEEP:-}" ]] || kind delete cluster --name $CLUSTER; rm -rf "$WORK"' EXIT
sleep 3

est() { # est <op> <csr-b64> [curl args...]
  local op=$1 csr=$2; shift 2
  curl -s -o "$WORK/out.b64" -w '%{http_code}' --cacert "$WORK/ca.crt" \
    --resolve "$HOST:18443:127.0.0.1" -H 'Content-Type: application/pkcs10' \
    --data-binary @"$csr" "$@" "https://$HOST:18443/.well-known/est/$op"
}
csr() { # csr <name> -> b64 file, key in $WORK/<name>.key
  openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/$1.key" 2>/dev/null
  openssl req -new -key "$WORK/$1.key" -subj "/CN=$1" -addext "subjectAltName=DNS:$1" -outform DER | base64 -w64 > "$WORK/$1.b64"
}
fail() { echo "FAIL: $*"; exit 1; }

echo "== allowlisted name: issued at once"
csr a.auto.e2e.test
[[ $(est simpleenroll "$WORK/a.auto.e2e.test.b64") == 200 ]] || fail "allowlist enroll"
base64 -d "$WORK/out.b64" | openssl pkcs7 -inform DER -print_certs > "$WORK/a.crt"
openssl verify -CAfile "$WORK/ca.crt" "$WORK/a.crt"

echo "== renewal with the issued certificate"
[[ $(est simplereenroll "$WORK/a.auto.e2e.test.b64" --cert "$WORK/a.crt" --key "$WORK/a.auto.e2e.test.key") == 200 ]] || fail "reenroll"

echo "== other name: 202, approve, 200"
csr gw1.home.e2e.test
[[ $(est simpleenroll "$WORK/gw1.home.e2e.test.b64") == 202 ]] || fail "expected 202"
CR=$(kubectl -n $NS get certificaterequest -l app.kubernetes.io/managed-by=est-server -o json \
  | jq -r '.items[] | select(.metadata.annotations["est-server/names"]=="gw1.home.e2e.test") | .metadata.name')
cmctl approve -n $NS "$CR"
for i in $(seq 30); do
  code=$(est simpleenroll "$WORK/gw1.home.e2e.test.b64"); [[ $code == 200 ]] && break; sleep 2
done
[[ $code == 200 ]] || fail "approved request not issued"

echo "PASS"
