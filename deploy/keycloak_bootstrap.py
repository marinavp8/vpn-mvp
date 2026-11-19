#!/usr/bin/env python3
"""Prepara Keycloak para el portal VPN y escribe el .env del host (se ejecuta EN el servidor).

- Crea (si no existe) el cliente confidencial OIDC `vpn` en el realm, con un mapper `groups`.
- Añade al cliente los mappers `groups` y `realm roles` en el id_token (el acceso puede ser por grupo o por rol
  de realm, p. ej. `staff`).
- Crea (si no existen) los grupos de GROUPS y mete en ADMIN_GROUP a los usuarios de ADMIN_USERS.
- Escribe ENV_FILE (0600) con OIDC_CLIENT_SECRET (leído de Keycloak) y SESSION_KEY (aleatoria).
  Si ENV_FILE ya existe, conserva SESSION_KEY y solo actualiza el secreto del cliente.

La contraseña del admin de Keycloak llega por KC_ADMIN_PASSWORD o, si no está, por stdin (nunca por argv).
Variables: KC_URL KC_REALM KC_ADMIN_USER KC_ADMIN_PASSWORD CLIENT_ID PUBLIC_URL GROUPS ADMIN_GROUP ADMIN_USERS ENV_FILE
"""
import json
import os
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request

KC = os.environ.get("KC_URL", "http://127.0.0.1:8080").rstrip("/")
REALM = os.environ.get("KC_REALM", "codecrypto")
CLIENT_ID = os.environ.get("CLIENT_ID", "vpn")
PUBLIC_URL = os.environ["PUBLIC_URL"].rstrip("/")
GROUPS = [g for g in os.environ.get("GROUPS", "vpn-admin").split(",") if g]
ADMIN_GROUP = os.environ.get("ADMIN_GROUP", "vpn-admin")
ADMIN_USERS = [u for u in os.environ.get("ADMIN_USERS", "").split(",") if u]

MAPPERS = [
    {"name": "groups", "protocol": "openid-connect", "protocolMapper": "oidc-group-membership-mapper",
     "config": {"claim.name": "groups", "full.path": "true", "id.token.claim": "true",
                "access.token.claim": "true", "userinfo.token.claim": "true"}},
    {"name": "realm roles (id token)", "protocol": "openid-connect", "protocolMapper": "oidc-usermodel-realm-role-mapper",
     "config": {"claim.name": "realm_access.roles", "multivalued": "true", "jsonType.label": "String",
                "id.token.claim": "true", "access.token.claim": "true", "userinfo.token.claim": "false"}},
]
ENV_FILE = os.environ["ENV_FILE"]


def call(method, path, token=None, body=None, form=None):
    data, headers = None, {}
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(KC + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            raw = r.read()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        sys.exit(f"{method} {path}: HTTP {e.code} {e.read()[:300]!r}")


def main():
    tok = call("POST", "/realms/master/protocol/openid-connect/token", form={
        "grant_type": "password", "client_id": "admin-cli",
        "username": os.environ.get("KC_ADMIN_USER", "admin"),
        "password": os.environ.get("KC_ADMIN_PASSWORD") or sys.stdin.readline().strip(),
    })["access_token"]
    base = f"/admin/realms/{REALM}"

    found = call("GET", f"{base}/clients?clientId={urllib.parse.quote(CLIENT_ID)}", tok)
    if not found:
        call("POST", f"{base}/clients", tok, {
            "clientId": CLIENT_ID, "name": "VPN alumnos", "protocol": "openid-connect", "enabled": True,
            "publicClient": False, "standardFlowEnabled": True, "directAccessGrantsEnabled": False,
            "serviceAccountsEnabled": False, "implicitFlowEnabled": False,
            "redirectUris": [PUBLIC_URL + "/callback"], "webOrigins": [PUBLIC_URL],
            "attributes": {"pkce.code.challenge.method": "S256", "post.logout.redirect.uris": PUBLIC_URL + "/*"},
        })
        found = call("GET", f"{base}/clients?clientId={urllib.parse.quote(CLIENT_ID)}", tok)
        print(f"cliente '{CLIENT_ID}' creado en el realm {REALM}")
    else:
        print(f"cliente '{CLIENT_ID}' ya existía")
    cid = found[0]["id"]
    have = {m["name"] for m in call("GET", f"{base}/clients/{cid}/protocol-mappers/models", tok)}
    for m in MAPPERS:
        if m["name"] not in have:
            call("POST", f"{base}/clients/{cid}/protocol-mappers/models", tok, m)
            print(f"mapper '{m['name']}' creado")
    secret = call("GET", f"{base}/clients/{cid}/client-secret", tok)["value"]

    groups = {g["name"]: g["id"] for g in call("GET", f"{base}/groups?briefRepresentation=true&max=1000", tok)}
    for g in GROUPS:
        if g not in groups:
            call("POST", f"{base}/groups", tok, {"name": g})
            print(f"grupo '{g}' creado")
    if ADMIN_USERS:
        groups = {g["name"]: g["id"] for g in call("GET", f"{base}/groups?briefRepresentation=true&max=1000", tok)}
        gid = groups[ADMIN_GROUP]
        members = {u["username"] for u in call("GET", f"{base}/groups/{gid}/members?max=1000&briefRepresentation=true", tok)}
        for name in ADMIN_USERS:
            if name in members:
                continue
            users = call("GET", f"{base}/users?username={urllib.parse.quote(name)}&exact=true", tok)
            if not users:
                sys.exit(f"usuario '{name}' no existe en el realm {REALM}")
            call("PUT", f"{base}/users/{users[0]['id']}/groups/{gid}", tok)
            print(f"usuario '{name}' añadido (creado) al grupo {ADMIN_GROUP}")

    env = {}
    if os.path.exists(ENV_FILE):
        for line in open(ENV_FILE):
            k, sep, v = line.strip().partition("=")
            if sep and not k.startswith("#"):
                env[k] = v
    env.setdefault("SESSION_KEY", secrets.token_hex(32))
    env["OIDC_CLIENT_SECRET"] = secret
    fd = os.open(ENV_FILE + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("# Generado por keycloak_bootstrap.py; no subir a git\n")
        f.writelines(f"{k}={v}\n" for k, v in env.items())
    os.replace(ENV_FILE + ".tmp", ENV_FILE)
    print(f"{ENV_FILE} actualizado (OIDC_CLIENT_SECRET, SESSION_KEY)")


if __name__ == "__main__":
    main()
