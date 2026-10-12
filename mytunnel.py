#!/usr/bin/env python3
"""
MyTunnel - minimal reverse tunnel (Iran <-> abroad style), carrier: tcp | udp.

  sudo mytunnel                -> interactive menu (setup / list / logs / remove)
  mytunnel server|client ...   -> run one tunnel in the foreground (used by systemd)

  server  (Iran side)  : listens on the tunnel port + exposes the public port
  client  (kharej side): dials the server, forwards traffic to the real service

  --proto tcp : tunnel carried over TCP, forwards TCP services
  --proto udp : tunnel carried over UDP, forwards UDP services (WireGuard, DNS, ...)

Auth: shared token (HMAC challenge for TCP, per-packet HMAC for UDP).
NOTE: payload is authenticated but NOT encrypted. Python 3.8+, no dependencies.
"""
import argparse, asyncio, hmac, hashlib, os, struct, time, logging

log = logging.getLogger("tun")


def mac(token, *parts):
    return hmac.new(token.encode(), b"|".join(parts), hashlib.sha256).digest()


def keepalive(w):
    import socket
    s = w.get_extra_info("socket")
    if s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)


async def pipe(r, w):
    try:
        while True:
            d = await r.read(65536)
            if not d:
                break
            w.write(d)
            await w.drain()
    except Exception:
        pass
    finally:
        try:
            w.close()
        except Exception:
            pass


async def bridge(r1, w1, r2, w2):
    await asyncio.gather(pipe(r1, w2), pipe(r2, w1))


# ───────────────────────────── TCP carrier ─────────────────────────────

async def tcp_server(a):
    ctrl = {"w": None}
    pending = {}

    async def on_tunnel(r, w):
        try:
            keepalive(w)
            nonce = os.urandom(16).hex().encode()
            w.write(nonce + b"\n")
            await w.drain()
            p = (await asyncio.wait_for(r.readline(), 10)).split()
            if len(p) == 2 and p[0] == b"CTRL":
                if not hmac.compare_digest(p[1], mac(a.token, b"CTRL", nonce).hex().encode()):
                    w.close()
                    return
                if ctrl["w"]:
                    ctrl["w"].close()
                ctrl["w"] = w
                w.write(b"OK\n")
                await w.drain()
                log.info("client connected")
                while await r.read(1024):
                    pass
                if ctrl["w"] is w:
                    ctrl["w"] = None
                log.info("client disconnected")
                w.close()
            elif len(p) == 3 and p[0] == b"DATA":
                cid = p[1]
                good = hmac.compare_digest(p[2], mac(a.token, b"DATA", nonce, cid).hex().encode())
                fut = pending.pop(cid, None)
                if good and fut and not fut.done():
                    fut.set_result((r, w))
                else:
                    w.close()
            else:
                w.close()
        except Exception:
            w.close()

    async def on_public(r, w):
        c = ctrl["w"]
        if c is None:
            w.close()
            return
        cid = os.urandom(8).hex().encode()
        fut = asyncio.get_running_loop().create_future()
        pending[cid] = fut
        try:
            c.write(b"NEW " + cid + b"\n")
            await c.drain()
            tr, tw = await asyncio.wait_for(fut, 10)
        except Exception:
            pending.pop(cid, None)
            w.close()
            return
        await bridge(r, w, tr, tw)

    await asyncio.start_server(on_tunnel, a.bind, a.tunnel_port)
    await asyncio.start_server(on_public, a.bind, a.public_port)
    log.info("tcp server: tunnel :%d  public :%d", a.tunnel_port, a.public_port)
    await asyncio.Event().wait()


async def tcp_handle_new(a, cid):
    try:
        lr, lw = await asyncio.open_connection(a.target_host, a.target_port)
        r, w = await asyncio.open_connection(a.server, a.tunnel_port)
        nonce = (await r.readline()).strip()
        w.write(b"DATA " + cid + b" " + mac(a.token, b"DATA", nonce, cid).hex().encode() + b"\n")
        await w.drain()
        await bridge(r, w, lr, lw)
    except Exception as e:
        log.warning("data conn failed: %s", e)


async def tcp_client(a):
    while True:
        try:
            r, w = await asyncio.open_connection(a.server, a.tunnel_port)
            keepalive(w)
            nonce = (await r.readline()).strip()
            w.write(b"CTRL " + mac(a.token, b"CTRL", nonce).hex().encode() + b"\n")
            await w.drain()
            if (await r.readline()).strip() != b"OK":
                raise RuntimeError("auth failed (token mismatch?)")
            log.info("connected to server")
            while True:
                line = await r.readline()
                if not line:
                    break
                p = line.split()
                if len(p) == 2 and p[0] == b"NEW":
                    asyncio.create_task(tcp_handle_new(a, p[1]))
        except Exception as e:
            log.warning("control connection: %s", e)
        await asyncio.sleep(3)


# ───────────────────────────── UDP carrier ─────────────────────────────
# packet = kind(1) + payload + mac8 ;  H = hello (payload: timestamp), D = data (payload: sid4 + bytes)

def pack(token, kind, payload):
    return kind + payload + mac(token, kind, payload)[:8]


def unpack(token, data):
    if len(data) < 9:
        return None
    kind, payload, tag = data[:1], data[1:-8], data[-8:]
    if not hmac.compare_digest(tag, mac(token, kind, payload)[:8]):
        return None
    return kind, payload


async def udp_server(a):
    loop = asyncio.get_running_loop()
    st = {"client": None, "by_addr": {}, "by_sid": {}, "next": 1, "tun": None, "pub": None}

    class Tunnel(asyncio.DatagramProtocol):
        def datagram_received(self, data, addr):
            m = unpack(a.token, data)
            if not m:
                return
            kind, payload = m
            if kind == b"H" and len(payload) == 8:
                if abs(time.time() - struct.unpack(">Q", payload)[0]) < 60:
                    if st["client"] != addr:
                        log.info("client registered from %s:%d", *addr[:2])
                    st["client"] = addr
            elif kind == b"D" and addr == st["client"] and len(payload) >= 4:
                s = st["by_sid"].get(struct.unpack(">I", payload[:4])[0])
                if s:
                    s[1] = time.time()
                    st["pub"].sendto(payload[4:], s[0])

    class Public(asyncio.DatagramProtocol):
        def datagram_received(self, data, addr):
            if st["client"] is None:
                return
            sid = st["by_addr"].get(addr)
            if sid is None:
                sid = st["next"]
                st["next"] += 1
                st["by_addr"][addr] = sid
                st["by_sid"][sid] = [addr, time.time()]
            st["by_sid"][sid][1] = time.time()
            st["tun"].sendto(pack(a.token, b"D", struct.pack(">I", sid) + data), st["client"])

    st["tun"], _ = await loop.create_datagram_endpoint(Tunnel, local_addr=(a.bind, a.tunnel_port))
    st["pub"], _ = await loop.create_datagram_endpoint(Public, local_addr=(a.bind, a.public_port))
    log.info("udp server: tunnel :%d  public :%d", a.tunnel_port, a.public_port)

    while True:
        await asyncio.sleep(30)
        now = time.time()
        for sid, (addr, last) in list(st["by_sid"].items()):
            if now - last > 60:
                st["by_sid"].pop(sid, None)
                st["by_addr"].pop(addr, None)


async def udp_client(a):
    loop = asyncio.get_running_loop()
    sessions = {}  # sid -> task(transport)
    last = {}
    tun = {}

    class Target(asyncio.DatagramProtocol):
        def __init__(self, sid):
            self.sid = sid

        def datagram_received(self, data, _):
            last[self.sid] = time.time()
            tun["t"].sendto(pack(a.token, b"D", struct.pack(">I", self.sid) + data))

    async def make(sid):
        t, _ = await loop.create_datagram_endpoint(
            lambda: Target(sid), remote_addr=(a.target_host, a.target_port))
        return t

    async def deliver(sid, payload):
        last[sid] = time.time()
        if sid not in sessions:
            sessions[sid] = asyncio.ensure_future(make(sid))
        (await sessions[sid]).sendto(payload)

    class Tunnel(asyncio.DatagramProtocol):
        def datagram_received(self, data, _):
            m = unpack(a.token, data)
            if m and m[0] == b"D" and len(m[1]) >= 4:
                asyncio.ensure_future(deliver(struct.unpack(">I", m[1][:4])[0], m[1][4:]))

    tun["t"], _ = await loop.create_datagram_endpoint(Tunnel, remote_addr=(a.server, a.tunnel_port))
    log.info("udp client -> %s:%d  target %s:%d", a.server, a.tunnel_port, a.target_host, a.target_port)

    n = 0
    while True:
        tun["t"].sendto(pack(a.token, b"H", struct.pack(">Q", int(time.time()))))
        await asyncio.sleep(5)
        n += 1
        if n % 6 == 0:
            now = time.time()
            for sid, f in list(sessions.items()):
                if now - last.get(sid, 0) > 60:
                    sessions.pop(sid, None)
                    (await f).close()


# ───────────────────────────── CLI / menu ─────────────────────────────
import re, secrets, shlex, socket, subprocess, sys

VERSION = "1.0.0"
BIN = "/usr/local/bin/mytunnel"
UNIT_DIR = "/etc/systemd/system"
PREFIX = "mytunnel-"


def sh(*cmd):
    return subprocess.run(cmd)


def ask(msg, default=None):
    s = input(msg + (f" [{default}]" if default else "") + ": ").strip()
    return s or default


def ask_int(msg, default=None):
    while True:
        v = ask(msg, str(default) if default else None)
        if v and v.isdigit() and 0 < int(v) < 65536:
            return int(v)
        print("  enter a port number (1-65535)")


def ask_name():
    while True:
        n = ask("Tunnel name (letters, digits, -)", "main")
        if re.fullmatch(r"[a-z0-9-]{1,30}", n or ""):
            return n
        print("  use only lowercase letters, digits and -")


def ask_proto():
    while True:
        p = (ask("Transport (tcp/udp)", "tcp") or "").lower()
        if p in ("tcp", "udp"):
            return p


def guess_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def install_service(name, argv):
    svc = f"{PREFIX}{name}.service"
    unit = (
        "[Unit]\n"
        f"Description=MyTunnel {name}\n"
        "After=network-online.target\nWants=network-online.target\n\n"
        "[Service]\n"
        f"ExecStart={BIN} " + " ".join(shlex.quote(x) for x in argv) + "\n"
        "Restart=always\nRestartSec=3\nLimitNOFILE=65535\n\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )
    with open(f"{UNIT_DIR}/{svc}", "w") as f:
        f.write(unit)
    sh("systemctl", "daemon-reload")
    sh("systemctl", "enable", "--now", svc)
    return svc


def setup_server():
    print("\n== Setup Iran (server) ==")
    name, proto = ask_name(), ask_proto()
    tport = ask_int("Tunnel port (kharej connects here)", 7000)
    pport = ask_int("Public port (users connect here)")
    token = secrets.token_hex(32)
    install_service(name, ["server", "--proto", proto, "--token", token,
                           "--tunnel-port", str(tport), "--public-port", str(pport)])
    ip = ask("This server's public IP/domain (for the client command)", guess_ip())
    print(f"\nServer running. Open {proto.upper()} port {tport} and {proto.upper()} port {pport} in the firewall.")
    print("\nOn the KHAREJ server run:  sudo mytunnel  ->  Setup Kharej, with:")
    print(f"  transport={proto}  server={ip}  tunnel port={tport}")
    print(f"  token={token}\n")


def setup_client():
    print("\n== Setup Kharej (client) ==")
    name, proto = ask_name(), ask_proto()
    server = ask("Iran server IP/domain")
    tport = ask_int("Tunnel port (same as on the Iran server)", 7000)
    target = ask("Real service on this server, host:port", "127.0.0.1:2096")
    token = ask("Token (copy from the Iran server)")
    if not (server and token and target and ":" in target):
        print("missing or invalid input")
        return
    install_service(name, ["client", "--proto", proto, "--token", token, "--server", server,
                           "--tunnel-port", str(tport), "--target", target])
    print("\nClient started. Check:  sudo mytunnel -> List tunnels\n")


def list_tunnels():
    sh("systemctl", "list-units", PREFIX + "*", "--all", "--no-pager")


def show_logs():
    n = ask("Tunnel name")
    sh("journalctl", "-u", f"{PREFIX}{n}", "-n", "40", "--no-pager")


def remove_tunnel():
    n = ask("Tunnel name to remove")
    svc = f"{PREFIX}{n}.service"
    sh("systemctl", "disable", "--now", svc)
    try:
        os.remove(f"{UNIT_DIR}/{svc}")
    except FileNotFoundError:
        pass
    sh("systemctl", "daemon-reload")
    print("removed")


def menu():
    if os.geteuid() != 0:
        sys.exit("Run with sudo:  sudo mytunnel")
    items = [("Setup Iran (server)", setup_server), ("Setup Kharej (client)", setup_client),
             ("List tunnels", list_tunnels), ("Logs", show_logs), ("Remove tunnel", remove_tunnel)]
    while True:
        print(f"\nMyTunnel v{VERSION}")
        for i, (t, _) in enumerate(items, 1):
            print(f" {i}. {t}")
        print(" 0. Exit")
        c = input("> ").strip()
        if c == "0":
            return
        if c.isdigit() and 1 <= int(c) <= len(items):
            items[int(c) - 1][1]()


def main():
    if len(sys.argv) == 1:
        return menu()
    ap = argparse.ArgumentParser(description="MyTunnel - minimal reverse tunnel (tcp|udp)")
    ap.add_argument("role", choices=["server", "client"])
    ap.add_argument("--proto", choices=["tcp", "udp"], default="tcp")
    ap.add_argument("--token", required=True)
    ap.add_argument("--tunnel-port", type=int, default=7000)
    ap.add_argument("--public-port", type=int, help="server: port users connect to")
    ap.add_argument("--bind", default="0.0.0.0", help="server: bind address")
    ap.add_argument("--server", help="client: server address")
    ap.add_argument("--target", help="client: real service, host:port")
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")

    if a.role == "server":
        if not a.public_port:
            ap.error("server needs --public-port")
        run = tcp_server if a.proto == "tcp" else udp_server
    else:
        if not (a.server and a.target):
            ap.error("client needs --server and --target")
        a.target_host, _, p = a.target.rpartition(":")
        a.target_port = int(p)
        run = tcp_client if a.proto == "tcp" else udp_client
    try:
        asyncio.run(run(a))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    if "--version" in sys.argv:
        print(VERSION)
    else:
        main()
