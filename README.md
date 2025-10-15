# list-proxmox-ips
---


## Pre Flight:
* Install python, pip and initialize the python virtual environment:
```
python3 -m .venv .venv
pip install -r requirements.txt
```

## Run the App:
* Edit your variables, surce the environment, and then run it:
  * `.env` file example (copy and paste):
```
export PROXMOX_HOST=192.168.1.34 #update this!!
export PROXMOX_USER='root@pam'
export PROXMOX_PASS=<redacted>
export PROXMOX_VERIFY_SSL=0
export PROXMOX_NODE=pve
```

 * Now run:

```
source .env
python app.py
```


## (Linux) Create systemd service:
* `vi /etc/systemd/system/list-proxmox-ips.service`
```
[Unit]
Description=Proxmox IP Directory (Flask)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=proxmox-ipdir
Group=proxmox-ipdir
WorkingDirectory=/opt/proxmox-ipdir
EnvironmentFile=/etc/default/proxmox-ipdir
ExecStart=/opt/proxmox-ipdir/.venv/bin/python /opt/proxmox-ipdir/app.py
Restart=on-failure
RestartSec=2
# --- hardening (safe defaults) ---
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true
MemoryDenyWriteExecute=true
CapabilityBoundingSet=
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
```

```
systemctl daemon-reload
systemctl enable --now proxmox-ipdir.service
systemctl status proxmox-ipdir.service --no-pager
journalctl -u proxmox-ipdir -f
```


