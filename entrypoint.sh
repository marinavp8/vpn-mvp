#!/bin/sh
# Reglas de red del contenedor VPN (su propio network namespace) y arranque del portal.
#   - Los clientes salen a internet con NAT por la interfaz por defecto del contenedor.
#   - NO pueden llegar a: redes privadas (red Docker "proyectos", VPC de GCP), metadatos de GCP
#     (169.254.169.254), otros clientes de la VPN, ni al propio contenedor (portal :8080).
#   - SMTP saliente (25) bloqueado contra spam.
set -eu

WG_INTERFACE=${WG_INTERFACE:-wg0}
WG_ADDRESS=${WG_ADDRESS:-10.66.0.1/22}
BLOCKED_CIDRS=${BLOCKED_CIDRS:-"10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 169.254.0.0/16 127.0.0.0/8 224.0.0.0/4 240.0.0.0/4 0.0.0.0/8"}
BLOCKED_TCP_PORTS=${BLOCKED_TCP_PORTS:-"25"}

WAN=$(ip -4 route show default | awk '{print $5; exit}')
[ -n "$WAN" ] || { echo "sin ruta por defecto" >&2; exit 1; }
[ "$(cat /proc/sys/net/ipv4/ip_forward)" = 1 ] || { echo "falta sysctl net.ipv4.ip_forward=1" >&2; exit 1; }

# Cadena propia, idempotente (el contenedor puede reiniciarse sin recrear el netns).
iptables -N VPN-FWD 2>/dev/null || iptables -F VPN-FWD
iptables -C FORWARD -i "$WG_INTERFACE" -j VPN-FWD 2>/dev/null || iptables -I FORWARD 1 -i "$WG_INTERFACE" -j VPN-FWD
iptables -C FORWARD -o "$WG_INTERFACE" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null \
  || iptables -I FORWARD 2 -o "$WG_INTERFACE" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -P FORWARD DROP

iptables -A VPN-FWD -o "$WG_INTERFACE" -j DROP            # cliente -> cliente
for c in $BLOCKED_CIDRS; do iptables -A VPN-FWD -d "$c" -j DROP; done
for p in $BLOCKED_TCP_PORTS; do iptables -A VPN-FWD -p tcp --dport "$p" -j REJECT --reject-with tcp-reset; done
iptables -A VPN-FWD -o "$WAN" -j ACCEPT
iptables -A VPN-FWD -j DROP

# Del túnel al propio contenedor: nada (solo respuestas).
iptables -N VPN-IN 2>/dev/null || iptables -F VPN-IN
iptables -C INPUT -i "$WG_INTERFACE" -j VPN-IN 2>/dev/null || iptables -I INPUT 1 -i "$WG_INTERFACE" -j VPN-IN
iptables -A VPN-IN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A VPN-IN -p icmp --icmp-type echo-request -j ACCEPT  # ping a 10.66.0.1 para diagnosticar
iptables -A VPN-IN -j DROP

iptables -t nat -C POSTROUTING -s "$WG_ADDRESS" -o "$WAN" -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s "$WG_ADDRESS" -o "$WAN" -j MASQUERADE
# MSS clamping: evita cuelgues de TLS por MTU (cliente 1380 dentro de la VPC de GCP 1460).
iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null \
  || iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

# IPv6: los clientes enrutan ::/0 por el túnel (para que no haya fugas) y aquí se descarta.
ip6tables -P FORWARD DROP 2>/dev/null || true

echo "firewall listo: wan=$WAN subred=$WG_ADDRESS"
exec /usr/local/bin/wgportal
