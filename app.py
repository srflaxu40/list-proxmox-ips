#!/usr/bin/env python3
"""
Proxmox IP Directory (API-backed)

Serves an HTML table (and /api JSON) listing VMs/LXCs on a Proxmox node
with Name, Hostname, Status, and IP addresses.

Auth options via environment (prefer API token):
  # Token auth (recommended)
  PROXMOX_HOST=192.168.1.34
  PROXMOX_USER=root@pam
  PROXMOX_TOKEN_ID=ipdir-token
  PROXMOX_TOKEN_SECRET=<secret>

  # Or password (temporary only; rotate afterward)
  PROXMOX_PASS=<password>

Other env:
  PROXMOX_NODE=pve           # filter to a single node (default: all)
  PROXMOX_PORT=8006          # default 8006
  PROXMOX_VERIFY_SSL=0       # set 0 to ignore self-signed certs

Supports .env files if python-dotenv is installed.
"""
import os
import re
from typing import Any, Dict, List
from flask import Flask, render_template_string, jsonify

# Optional .env support
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

try:
    from proxmoxer import ProxmoxAPI
    from proxmoxer.core import AuthenticationError
except Exception as e:
    raise SystemExit("Missing dependency: pip install proxmoxer flask python-dotenv")

app = Flask(__name__)

TABLE_TMPL = """
<!doctype html>
<html>
  <head>
    <meta charset=\"utf-8\" />
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
    <title>Proxmox IP Directory</title>
    <style>
      :root { --bd:#e5e7eb; --muted:#6b7280; }
      body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, Arial, sans-serif; margin: 24px; }
      h1 { margin: 0 0 10px; }
      table { border-collapse: collapse; width: 100%; }
      th, td { border: 1px solid var(--bd); padding: 8px 10px; text-align: left; font-size: 14px; }
      th { background: #f3f4f6; }
      tr:nth-child(even) { background: #fafafa; }
      .badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 12px; border: 1px solid var(--bd); }
      .up { background: #ecfdf5; border-color: #10b981; color: #065f46; }
      .down { background: #fef2f2; border-color: #ef4444; color: #991b1b; }
      footer { margin-top: 16px; color: var(--muted); font-size: 12px; }
      .controls { margin-bottom: 12px; display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
      input[type=\"text\"] { padding: 6px 8px; border: 1px solid var(--bd); border-radius: 6px; min-width: 240px; }
      .small { font-size: 12px; color: var(--muted); }
      button { padding: 6px 10px; border: 1px solid var(--bd); background: white; border-radius: 6px; cursor: pointer; }
    </style>
  </head>
  <body>
    <h1>Proxmox IP Directory</h1>
    <div class=\"controls\">
      <input id=\"search\" type=\"text\" placeholder=\"Filter by name, node, IP, or VMID…\" oninput=\"filter()\" />
      <span class=\"small\">{{ rows|length }} items</span>
      <a href=\"/api\" class=\"small\">JSON API</a>
      <button onclick=\"refresh()\">Refresh</button>
    </div>
    <table id=\"tbl\">
      <thead>
        <tr>
          <th>Node</th>
          <th>Type</th>
          <th>VMID</th>
          <th>Name / Hostname</th>
          <th>Status</th>
          <th>IPs</th>
        </tr>
      </thead>
      <tbody>
      {% for r in rows %}
        <tr>
          <td>{{ r.node }}</td>
          <td>{{ r.vtype }}</td>
          <td>{{ r.vmid }}</td>
          <td>{{ r.display_name }}</td>
          <td><span class=\"badge {{ 'up' if r.status == 'running' else 'down' }}\">{{ r.status }}</span></td>
          <td>{{ ', '.join(r.ips) if r.ips else '' }}</td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
    <footer>
      QEMU IPs require the Guest Agent inside the VM and enabled in Proxmox (Options → QEMU Guest Agent = Enabled).
    </footer>
    <script>
      function refresh(){ location.reload(); }
      function filter(){
        const q = document.getElementById('search').value.toLowerCase();
        const rows = document.querySelectorAll('#tbl tbody tr');
        rows.forEach(tr => {
          const text = tr.innerText.toLowerCase();
          tr.style.display = text.includes(q) ? '' : 'none';
        });
      }
    </script>
  </body>
</html>
"""

IPV4_RE = re.compile(r"^(?!127\.|169\.254\.)((?:\d{1,3}\.){3}\d{1,3})$")


def get_proxmox():
    host   = os.environ.get("PROXMOX_HOST", "127.0.0.1")
    user   = os.environ.get("PROXMOX_USER", "root@pam")
    verify = os.environ.get("PROXMOX_VERIFY_SSL", "1") != "0"
    port   = int(os.environ.get("PROXMOX_PORT", "8006"))

    token_name   = os.environ.get("PROXMOX_TOKEN_ID")
    token_secret = os.environ.get("PROXMOX_TOKEN_SECRET")
    password     = os.environ.get("PROXMOX_PASS")
    otp          = os.environ.get("PROXMOX_OTP")

    try:
        if token_name and token_secret:
            return ProxmoxAPI(
                host, user=user, token_name=token_name, token_value=token_secret,
                verify_ssl=verify, port=port
            )
        if password:
            return ProxmoxAPI(
                host, user=user, password=password, otp=otp,
                verify_ssl=verify, port=port
            )
        raise RuntimeError("No credentials: set PROXMOX_TOKEN_ID/PROXMOX_TOKEN_SECRET (preferred) or PROXMOX_PASS.")
    except AuthenticationError as e:
        raise RuntimeError(
            f"Auth failed for '{user}' at https://{host}:{port} (check realm like root@pam, token/password, 2FA)."
        ) from e


def extract_ips_from_agent(agent_result: Any) -> List[str]:
    ips: List[str] = []
    if not isinstance(agent_result, dict):
        return ips
    result = agent_result.get("result") or agent_result
    if isinstance(result, list):
        for iface in result:
            addrs = iface.get("ip-addresses") or []
            for a in addrs:
                ip = a.get("ip-address")
                if ip and ":" not in ip and IPV4_RE.match(ip):
                    ips.append(ip)
    return list(dict.fromkeys(ips))


def collect_rows() -> List[Dict[str, Any]]:
    proxmox = get_proxmox()
    want_node = os.environ.get("PROXMOX_NODE")  # e.g., "pve"
    rows: List[Dict[str, Any]] = []

    resources = proxmox.cluster.resources.get(type="vm")  # qemu + lxc
    for item in resources:
        node = item.get("node")
        if want_node and node != want_node:
            continue
        vtype = item.get("type")
        vmid = int(item.get("vmid"))
        name = item.get("name") or ""
        status = item.get("status", "")
        hostname = ""
        ips: List[str] = []

        if vtype == "qemu":
            # Prefer guest agent for live IPs + hostname
            try:
                agent_if = proxmox.nodes(node).qemu(vmid).agent("network-get-interfaces").get()
                ips = extract_ips_from_agent(agent_if)
            except Exception:
                ips = []
            try:
                hn = proxmox.nodes(node).qemu(vmid).agent("get-host-name").get()
                if isinstance(hn, dict):
                    hostname = hn.get("result", {}).get("host-name", "") or hn.get("host-name", "")
            except Exception:
                hostname = ""
        elif vtype == "lxc":
            try:
                st = proxmox.nodes(node).lxc(vmid).status.current.get()
                if isinstance(st, dict):
                    ipv = st.get("ip")
                    if isinstance(ipv, str):
                        m = re.search(r"(\d+\.\d+\.\d+\.\d+)", ipv)
                        if m:
                            ips.append(m.group(1))
                    ips_arr = st.get("ips") or []
                    for it in ips_arr:
                        if isinstance(it, dict):
                            addr = it.get("ip")
                            if addr and IPV4_RE.match(addr):
                                ips.append(addr)
                if not ips:
                    cfg = proxmox.nodes(node).lxc(vmid).config.get()
                    # hostname from config if available
                    hostname = cfg.get("hostname", hostname)
                    # parse static ipv4 from net* lines
                    for k, v in cfg.items():
                        if isinstance(v, str) and "ip=" in v:
                            m = re.search(r"ip=(\d+\.\d+\.\d+\.\d+)", v)
                            if m:
                                ips.append(m.group(1))
            except Exception:
                pass

        display_name = name
        if hostname and hostname.lower() != (name or "").lower():
            display_name = f"{name} ({hostname})" if name else hostname

        rows.append({
            "node": node,
            "vtype": vtype,
            "vmid": vmid,
            "name": name,
            "hostname": hostname,
            "display_name": display_name,
            "status": status,
            "ips": list(dict.fromkeys(ips)),
        })

    rows.sort(key=lambda r: (r["node"], r["vtype"], r["vmid"]))
    return rows


@app.route("/")
def index():
    rows = collect_rows()
    return render_template_string(TABLE_TMPL, rows=rows)


@app.route("/api")
def api():
    return jsonify(collect_rows())


@app.get("/health")
def health():
    try:
        _ = collect_rows()
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}, 500


if __name__ == "__main__":
    # Bind on all interfaces (adjust port if needed)
    app.run(host="0.0.0.0", port=8081)

