"use strict";
// Portal VPN: la clave privada se genera aquí (WebCrypto X25519) y nunca se envía al servidor.

const $ = (id) => document.getElementById(id);
let me = null;

async function api(path, opts = {}) {
  const res = await fetch(path, { credentials: "same-origin", headers: { "Content-Type": "application/json" }, ...opts });
  if (res.status === 401) { location.href = "/login"; throw new Error("sesión caducada"); }
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
  return body;
}

const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));

async function generateKeyPair() {
  const kp = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey));
  const pub = await crypto.subtle.exportKey("raw", kp.publicKey);
  return { privateKey: b64(pkcs8.slice(-32)), publicKey: b64(pub) }; // PKCS#8 X25519: los 32 últimos bytes son la clave
}

function buildConf(dev, privateKey) {
  const s = me.server;
  return [
    "[Interface]",
    privateKey ? `PrivateKey = ${privateKey}` : "# PrivateKey = <tu clave privada>",
    `Address = ${dev.ip}/32`,
    `DNS = ${s.dns}`,
    `MTU = ${s.mtu}`,
    "",
    "[Peer]",
    `PublicKey = ${s.publicKey}`,
    `Endpoint = ${s.endpoint}`,
    `AllowedIPs = ${s.allowedIPs}`,
    "PersistentKeepalive = 25",
    "",
  ].join("\n");
}

function ago(iso) {
  const t = Date.parse(iso);
  if (!t || t < 0 || new Date(iso).getUTCFullYear() < 2000) return "nunca";
  const s = Math.round((Date.now() - t) / 1000);
  if (s < 60) return `hace ${s} s`;
  if (s < 3600) return `hace ${Math.round(s / 60)} min`;
  if (s < 86400) return `hace ${Math.round(s / 3600)} h`;
  return new Date(t).toLocaleString();
}

function bytes(n) {
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
}

function el(tag, props = {}, ...children) {
  const e = document.createElement(tag);
  Object.assign(e, props);
  e.append(...children);
  return e;
}

async function remove(dev) {
  const who = dev.username && dev.username !== me.username ? ` de ${dev.username}` : "";
  if (!confirm(`¿Revocar "${dev.name}"${who}? Dejará de poder conectarse.`)) return;
  try {
    await api(`/api/devices/${encodeURIComponent(dev.id)}`, { method: "DELETE" });
    await refresh();
  } catch (e) { alert(e.message); }
}

async function refresh() {
  const devs = await api("/api/devices");
  const ul = $("devices");
  ul.replaceChildren(...devs.map((d) =>
    el("li", {},
      el("span", { className: "status" + (d.online ? " on" : ""), title: d.online ? "conectado" : "desconectado" }),
      el("div", { className: "meta" },
        el("div", { className: "name", textContent: d.name }),
        el("div", { className: "sub", textContent:
          `${d.ip} · último handshake ${ago(d.lastHandshake)} · ↓ ${bytes(d.rxBytes)} ↑ ${bytes(d.txBytes)}` })),
      el("button", { className: "danger", textContent: "Revocar", onclick: () => remove(d) }))));
  $("empty").hidden = devs.length > 0;
  $("add-card").hidden = devs.length >= me.maxDevices && $("result").hidden;

  if (me.admin) {
    const all = await api("/api/admin/devices");
    $("all").replaceChildren(...all.map((d) =>
      el("tr", {},
        el("td", { textContent: d.username }),
        el("td", { textContent: d.name }),
        el("td", { textContent: d.ip }),
        el("td", { textContent: ago(d.lastHandshake) + (d.endpoint ? ` (${d.endpoint})` : "") }),
        el("td", { textContent: `${bytes(d.rxBytes)} / ${bytes(d.txBytes)}` }),
        el("td", {}, el("button", { className: "danger", textContent: "Revocar", onclick: () => remove(d) })))));
    $("admin").hidden = false;
  }
}

function showResult(dev, privateKey) {
  const conf = buildConf(dev, privateKey);
  $("r-name").textContent = dev.name;
  $("conf").textContent = conf;
  const qr = qrcode(0, "M");
  qr.addData(conf);
  qr.make();
  $("qr").replaceChildren(el("img", { src: qr.createDataURL(4, 0), alt: "QR de la configuración WireGuard" }));
  $("qr").hidden = !privateKey;
  $("download").onclick = () => {
    const a = el("a", {
      href: URL.createObjectURL(new Blob([conf], { type: "text/plain" })),
      download: `codecrypto-${dev.name.replace(/[^a-z0-9_-]+/gi, "-").slice(0, 15) || "vpn"}.conf`,
    });
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  };
  $("copy").onclick = async () => { await navigator.clipboard.writeText(conf); $("copy").textContent = "Copiado"; };
  $("done").onclick = () => {
    $("result").hidden = true;
    $("conf").textContent = "";
    $("qr").replaceChildren();
    refresh();
  };
  $("result").hidden = false;
  $("result").scrollIntoView({ behavior: "smooth" });
}

$("add").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("error").textContent = "";
  $("add-btn").disabled = true;
  try {
    let keys = { privateKey: null, publicKey: $("pubkey").value.trim() };
    if (!keys.publicKey) {
      try { keys = await generateKeyPair(); }
      catch { throw new Error("Tu navegador no puede generar claves X25519. Actualízalo o usa la opción avanzada con tu propia clave pública."); }
    }
    const dev = await api("/api/devices", { method: "POST", body: JSON.stringify({ name: $("name").value, publicKey: keys.publicKey }) });
    $("add").reset();
    showResult(dev, keys.privateKey);
    keys = null;
    await refresh();
  } catch (e) {
    $("error").textContent = e.message;
  } finally {
    $("add-btn").disabled = false;
  }
});

(async () => {
  try {
    me = await api("/api/me");
    $("username").textContent = me.username;
    $("max").textContent = me.maxDevices;
    await refresh();
    setInterval(() => refresh().catch(() => {}), 30000);
  } catch (e) {
    $("error").textContent = e.message;
  }
})();
