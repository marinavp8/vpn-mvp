# VPN de alumnos — WireGuard + portal de autoservicio

## Guía
**👉 [https://estaticos.codecrypto.academy/vpn-arquitectura/](https://estaticos.codecrypto.academy/vpn-arquitectura/)**
— explicación interactiva de la arquitectura para alumnos (viaje de un paquete, firewall, AllowedIPs, claves).
Fuente: [`docs/arquitectura.html`](docs/arquitectura.html).

Portal: [https://vpn.alumnos.codecrypto.academy](https://vpn.alumnos.codecrypto.academy)

VPN de **salida a internet** para alumnos en `alumnos-vm` (35.255.164.51). El alumno entra en
**https://vpn.alumnos.codecrypto.academy** con su usuario de Keycloak (realm `codecrypto`), crea un dispositivo
y descarga la configuración (o escanea el QR) para la app oficial de WireGuard.

```
alumno ──HTTPS──► Traefik :443 ──► contenedor vpn :8080 (portal Go, login OIDC Keycloak)
alumno ══UDP 51820 (WireGuard)══► contenedor vpn: wg0 10.66.0.1/22 ──NAT──► internet
                                                 └─✗ redes privadas, metadatos GCP, otros alumnos, SMTP
```

## Diseño
- **La clave privada nunca sale del navegador**: se genera con WebCrypto (X25519), el portal solo recibe
  y guarda la pública. El `.conf`/QR se arma en el navegador. Opción avanzada: pegar tu propia clave pública.
- Un único contenedor (`cap_drop: ALL` + `NET_ADMIN`, FS de solo lectura) con su propio network namespace:
  la interfaz `wg0` del kernel la gestiona el portal con `wgctrl`; el firewall está en `entrypoint.sh`.
- Estado en el volumen `vpn_data`: `peers.json` (dispositivos) y `server.key` (clave del servidor, 0600).
  Al arrancar, `wg0` se sincroniza exactamente con `peers.json`.
- Acceso: **rol de realm `staff`** de Keycloak (`OIDC_ALLOWED_GROUPS` acepta grupos o roles de realm; el cliente
  lleva un mapper que mete `realm_access.roles` en el id_token). Administradores: grupo `vpn-admin`
  (hoy `jviejo@gmail.com`), que ven y revocan todos los dispositivos.
- Máximo 3 dispositivos por alumno, IPs de `10.66.0.0/22` (~1000 dispositivos).

### Firewall (dentro del contenedor)
| Desde el túnel hacia | |
|---|---|
| Internet | ✅ NAT por la interfaz por defecto |
| 10/8, 172.16/12, 192.168/16, 100.64/10, 169.254/16 (red `proyectos`, VPC, metadatos GCP) | ❌ |
| Otros clientes de la VPN | ❌ |
| El propio contenedor (portal) | ❌ (solo ping a 10.66.0.1) |
| TCP 25 (SMTP) | ❌ reset |
| IPv6 | ❌ (los clientes enrutan `::/0` por el túnel para evitar fugas) |

**Split de redes privadas en el cliente** (`vpn_client_allowed_ips` en el rol): el cliente enruta por el túnel todo
internet **menos** 10/8, 172.16/12, 192.168/16, 100.64/10 (Tailscale), 169.254/16 y multicast, más `10.66.0.0/22`.
Motivo: con Tailscale activo, macOS usa su DNS (100.100.100.100), que reenvía al router de casa (192.168.x);
si eso entra en el túnel, el servidor lo descarta y **se queda sin DNS**. Así conviven Tailscale, la LAN y la VPN.
El DNS en ese caso sale por Tailscale/router, no por la VPN.

## Estructura
```
cmd/wgportal/      main: config → peers.json → wg0 → OIDC → HTTP
internal/config    variables de entorno
internal/store     dispositivos + asignación de IPs (con tests)
internal/wg        interfaz WireGuard (wgctrl)
internal/auth      OIDC con PKCE + cookie de sesión firmada (HMAC), 8 h
internal/server    API JSON y páginas (CSP estricta, comprobación de Origin)
web/static         interfaz (HTML/CSS/JS sin dependencias, qrcode-generator 1.4.4 vendorizado)
entrypoint.sh      reglas iptables + exec del portal
deploy/keycloak_bootstrap.py   crea cliente OIDC y grupos y escribe .env en el servidor
```

## API
| Método | Ruta | |
|---|---|---|
| GET | `/api/me` | usuario + parámetros del servidor (clave pública, endpoint, DNS, MTU) |
| GET | `/api/devices` | mis dispositivos con estado (handshake, tráfico) |
| POST | `/api/devices` | `{name, publicKey}` → alta (requiere `Origin` = PUBLIC_URL) |
| DELETE | `/api/devices/{id}` | baja (dueño o admin) |
| GET | `/api/admin/devices` | todos (admin) |

## Despliegue (rol Ansible `vpn` en `~/plataforma/infra/alumnos`)
```bash
cd ~/plataforma/infra/alumnos/terraform && terraform apply      # regla UDP 51820 + etiqueta "vpn" en la VM
cd ../ansible && ansible-playbook site.yml --tags vpn
```
El rol carga el módulo `wireguard`, copia este código al servidor (`/opt/platform/vpn/src`), ejecuta
`keycloak_bootstrap.py` (cliente `vpn` con PKCE y mappers `groups` + `realm roles`, grupo `vpn-admin` con
`vpn_admin_users`, `.env` 0600 con `OIDC_CLIENT_SECRET` y `SESSION_KEY`) y levanta el contenedor.
Dar acceso a alguien = darle el rol `staff` (o cambiar `vpn_allowed_groups`).

Operación en el servidor:
```bash
docker logs -f vpn                       # logins, altas y bajas (JSON)
docker exec vpn wg show                  # peers, handshakes, tráfico
docker exec vpn iptables -L VPN-FWD -v -n
```

## Variables de entorno
`PUBLIC_URL`, `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_ALLOWED_GROUPS`, `OIDC_ADMIN_GROUPS`,
`SESSION_KEY` (hex ≥ 32 bytes), `WG_ENDPOINT`, `WG_PORT` (51820), `WG_ADDRESS` (10.66.0.1/22), `WG_DNS`,
`WG_MTU` (1380), `WG_MAX_DEVICES` (3), `WG_CLIENT_ALLOWED_IPS` (`0.0.0.0/0, ::/0`), `DATA_DIR` (/data),
`LISTEN` (:8080). En `entrypoint.sh`: `BLOCKED_CIDRS`, `BLOCKED_TCP_PORTS`.

## Verificado en local (Docker Desktop, OIDC simulado con mock-oauth2-server)
- Handshake real cliente↔servidor, ping a 10.66.0.1, HTTPS a internet por el túnel.
- Bloqueados: red Docker interna del servidor, 169.254.169.254, portal por el túnel, SMTP 25.
- Login OIDC completo (PKCE + nonce), alta por API → peer activo en `wg0` y conectando; baja → peer eliminado.
- Rechazos: POST sin `Origin`, clave inválida, clave duplicada, admin sin grupo, cookie manipulada.
- Reinicio del contenedor: misma clave de servidor y peers restaurados.
- Claves WebCrypto de `app.js` == `wg pubkey` de la misma privada.
- Funciona con `cap_drop: ALL` + `NET_ADMIN` y `read_only: true`.

## Pendiente / a valorar
- **Coste de salida de GCP** (~0,08–0,12 $/GB): todo el tráfico de los alumnos se factura como egress.
  Considerar límite de ancho de banda (`tc`) o cuota por alumno.
- Todo sale con la IP de la academia: política de uso aceptable para los alumnos.
- Revocar dispositivos cuando alguien pierde el rol `staff` (hoy solo se impide entrar al portal; sus túneles
  siguen activos hasta que un admin los revoque).
