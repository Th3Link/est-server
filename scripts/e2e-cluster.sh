#!/usr/bin/env bash
# A throwaway dual-stack kind cluster with cert-manager (without its
# built-in approver) and the EstClient CRD for the end-to-end tests. Its kubeconfig goes to
# target/e2e/kubeconfig; your own ~/.kube/config is left alone.
#
#   scripts/e2e-cluster.sh up      # create (or reuse) the cluster
#   EST_E2E_KUBECONFIG=target/e2e/kubeconfig cargo test -- --ignored
#   scripts/e2e-cluster.sh down    # delete it
#
# Needs: docker, kind, helm, kubectl.
set -euo pipefail

CLUSTER=${EST_E2E_CLUSTER:-est-e2e}
CERT_MANAGER_VERSION=${CERT_MANAGER_VERSION:-v1.21.3}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
KUBECONFIG_FILE="$ROOT/target/e2e/kubeconfig"
export KUBECONFIG="$KUBECONFIG_FILE"

up() {
  mkdir -p "$(dirname "$KUBECONFIG_FILE")"
  if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
    kind create cluster --name "$CLUSTER" --kubeconfig "$KUBECONFIG_FILE" --wait 120s --config - <<YAML
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  ipFamily: dual
YAML
  else
    kind get kubeconfig --name "$CLUSTER" > "$KUBECONFIG_FILE"
  fi
  helm upgrade --install cert-manager cert-manager \
    --repo https://charts.jetstack.io --version "$CERT_MANAGER_VERSION" \
    -n cert-manager --create-namespace --wait --timeout 5m \
    --set crds.enabled=true \
    --set 'extraArgs[0]=--controllers=*\,-certificaterequests-approver'
  kubectl apply -f "$ROOT/deploy/helm/est-server/crds/"
  echo
  echo "export EST_E2E_KUBECONFIG=$KUBECONFIG_FILE"
}

down() {
  kind delete cluster --name "$CLUSTER" --kubeconfig "$KUBECONFIG_FILE"
  rm -f "$KUBECONFIG_FILE"
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  *) echo "usage: $0 up|down" >&2; exit 2 ;;
esac
