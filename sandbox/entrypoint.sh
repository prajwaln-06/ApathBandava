#!/bin/sh
# Egress firewall (NFR-2): public internet only. Applied as root, then root is dropped for good.
set -eu
fw() {
  iptables -F OUTPUT
  iptables -A OUTPUT -o lo -j ACCEPT
  iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  for net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10 0.0.0.0/8 224.0.0.0/4 240.0.0.0/4 198.18.0.0/15; do
    iptables -A OUTPUT -d "$net" -j REJECT
  done
  iptables -A OUTPUT -j ACCEPT
  ip6tables -F OUTPUT 2>/dev/null || true
  ip6tables -A OUTPUT -o lo -j ACCEPT 2>/dev/null || true
  ip6tables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
  ip6tables -A OUTPUT -j REJECT 2>/dev/null || true
}
if ! fw; then
  if [ "${SANDBOX_ALLOW_NO_FIREWALL:-0}" = "1" ]; then
    echo "WARNING: iptables unavailable; relying on in-app IP checks only" >&2
  else
    echo "FATAL: could not install egress firewall (needs NET_ADMIN). Refusing to start." >&2
    exit 1
  fi
fi
echo "egress firewall installed"
exec setpriv --reuid=pwuser --regid=pwuser --init-groups --inh-caps=-all --bounding-set=-all \
  env HOME=/tmp uvicorn app:app --host 0.0.0.0 --port 9000 --no-access-log
