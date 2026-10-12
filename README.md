MyTunnel
Minimal reverse tunnel between an Iran server and a kharej server, with a selectable carrier: TCP or UDP.
```
users ──▶ IRAN server ══ tunnel (tcp|udp) ══▶ KHAREJ server ──▶ real service
```
The kharej server dials the Iran server (no inbound port needed on kharej).
Install (both servers)
```
bash <(curl -fsSL https://raw.githubusercontent.com/eilyayun/claude-tun/main/install.sh)
```
Then open the menu any time: `sudo mytunnel`
Setup
Iran server: `sudo mytunnel` → Setup Iran → name, transport, tunnel port, public port. A token is generated and printed.
Kharej server: `sudo mytunnel` → Setup Kharej → same transport, Iran IP, same tunnel port, the real service (`127.0.0.1:PORT`), and the token.
Check: List tunnels / Logs.
Each tunnel runs as a systemd service (`mytunnel-<name>`), restarts on failure and survives reboot.
Transports
Transport	Carries	Use for
`tcp`	TCP	x-ui, SSH, web, anything TCP
`udp`	UDP	WireGuard, DNS, games
UDP mode forwards UDP services only (TCP over UDP would need a reliability layer such as KCP).
Open the tunnel port and the public port (same protocol) in the Iran server firewall.
Manual run
```
mytunnel server --proto tcp --token TOKEN --tunnel-port 7000 --public-port 443
mytunnel client --proto tcp --token TOKEN --server IRAN_IP --tunnel-port 7000 --target 127.0.0.1:2096
```
Offline install (server can't reach GitHub)
```
scp install.sh mytunnel.py root@SERVER:/root/
ssh root@SERVER "cd /root && bash install.sh --local"
```
Security note
The token authenticates both ends and protects against tampering, but traffic is not encrypted by the tunnel.
Run encrypted protocols (VLESS+TLS, WireGuard, SSH...) through it.
License
Add a LICENSE file (e.g. MIT) before publishing.
