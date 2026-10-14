# HoneyTrap — Live Lab Honeypot Dashboard

A lightweight, real-time SSH honeypot with a professional Security Operations Center (SOC) dashboard for capturing and visualizing unauthorized access attempts. Designed for cybersecurity labs, demos, and educational purposes.

---

## Features

### SSH Honeypot (Port 2222)
- Simulated SSH server that captures all login attempts (username/password)
- Configurable "trap" credentials that allow attackers to "succeed" and enter a **sandboxed fake shell**
- Fake shell returns realistic Linux command output (`whoami`, `ls -la`, `cat /etc/passwd`, `ps aux`, etc.)
- The fake shell is **strictly sandboxed** — it never touches the host OS

### Real-Time Dashboard
- **Live Attack Feed** — terminal-styled scrolling log of every connection, auth attempt, and session
- **Command Logger** — shows exactly what commands the attacker types after "authenticating"
- **Metrics Cards** — Total Attempts, Unique IPs, Active Sessions, Commands Logged (with animated counters)
- **Top Usernames / Passwords / IPs** — ranked lists with progress bars
- **Attempts Over Time** — live-updating Chart.js line chart
- **Block IP** — simulates adding an IP to a blocklist and drops their connection
- **Export Report** — download session data as CSV or JSON

### Tech Stack
| Component | Technology |
|-----------|-----------|
| Backend | Python 3, FastAPI, Paramiko |
| WebSockets | FastAPI native WebSocket |
| Frontend | Vanilla HTML/CSS/JS, Chart.js, Lucide Icons |
| Fonts | Inter, JetBrains Mono (Google Fonts) |
| Data | In-memory (no database required) |

---

## Quick Start

### Prerequisites
- **Python 3.10+** installed
- `pip` available

### 1. Install Dependencies

```bash
cd "d:\LAB REPORTS\ZYVORIX TEC INTERNSHIP\WEEK 6 TOOL"
pip install -r requirements.txt
```

Or install manually:
```bash
pip install fastapi uvicorn websockets python-multipart paramiko jinja2 aiofiles
```

### 2. Start the Server

```bash
python server.py
```

This starts **both** services:
- **SSH Honeypot** on `port 2222`
- **Dashboard Web Server** on `http://localhost:3000`

### 3. Open the Dashboard

Navigate to **http://localhost:3000** in your browser.

### 4. Attack It!

#### From Kali Linux (or any machine):

**Single SSH attempt:**
```bash
ssh -p 2222 root@<YOUR_IP>
# Try password: root (will succeed and give you a fake shell)
# Try password: anything_else (will fail and be logged)
```

**Brute-force with Hydra:**
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<YOUR_IP>:2222 -t 4
```

**Brute-force with Medusa:**
```bash
medusa -h <YOUR_IP> -u root -P /usr/share/wordlists/rockyou.txt -M ssh -n 2222
```

**Ncrack:**
```bash
ncrack -p 2222 --user root -P /usr/share/wordlists/rockyou.txt <YOUR_IP>
```

**Run the included test script (simulates a full attack):**
```bash
python test_attack.py
```

Replace `<YOUR_IP>` with your machine's IP address (use `ipconfig` on Windows or `ip addr` on Linux).

---

## Trap Credentials

These credentials will "succeed" and drop the attacker into a fake shell:

| Username | Password |
|----------|----------|
| root | root |
| admin | admin |
| root | toor |
| root | 123456 |
| ubuntu | ubuntu |
| test | test |

All other credential combinations are **rejected** and logged.

---

## Fake Shell Commands

When an attacker logs in with trap credentials, they get an interactive shell that responds to:

| Command | Fake Response |
|---------|--------------|
| `whoami` | Current username |
| `id` | uid=0(root) ... |
| `uname -a` | Linux prod-db-01 5.15.0-83-generic ... |
| `ls -la` | Fake directory listing |
| `cat /etc/passwd` | Fake system users |
| `ps aux` | Fake running processes (sshd, mysqld, apache2) |
| `netstat -tlnp` | Fake listening ports (22, 80, 3306, 443) |
| `cat .bash_history` | Suspicious fake command history |
| `ifconfig` / `ip addr` | Fake network interfaces |
| `df -h` | Fake disk usage |
| `free -m` | Fake memory usage |
| `env` | Fake environment variables |
| `cat /etc/os-release` | Ubuntu 22.04.3 LTS |
| `uptime` | Fake uptime (43 days) |

Any unrecognized command returns `bash: <cmd>: command not found`.

---

## Project Structure

```
WEEK 6 TOOL/
├── server.py            # Main backend: FastAPI + SSH Honeypot + WebSocket
├── requirements.txt     # Python dependencies
├── test_attack.py       # Demo attack script (brute-force + commands)
├── host_key             # Auto-generated SSH host key (created on first run)
└── frontend/
    └── index.html       # Complete SOC dashboard (single-file)
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Serves the dashboard |
| GET | `/api/state` | Full state snapshot (JSON) |
| POST | `/api/block` | Block an IP `{"ip": "x.x.x.x"}` |
| POST | `/api/unblock` | Unblock an IP `{"ip": "x.x.x.x"}` |
| GET | `/api/export/csv` | Download CSV report |
| GET | `/api/export/json` | Download JSON report |
| WS | `/ws` | WebSocket for real-time events |

---

## WebSocket Events

| Event | Direction | Description |
|-------|-----------|-------------|
| `initial_state` | Server → Client | Full state on connect |
| `new_attempt` | Server → Client | New login attempt |
| `new_command` | Server → Client | New shell command captured |
| `stats` | Server → Client | Updated metrics |
| `top_usernames` | Server → Client | Updated username rankings |
| `top_passwords` | Server → Client | Updated password rankings |
| `top_ips` | Server → Client | Updated IP rankings |
| `attempts_over_time` | Server → Client | Updated time series |
| `connection_opened` | Server → Client | New shell session |
| `connection_closed` | Server → Client | Session ended |
| `ip_blocked` | Server → Client | IP was blocked |
| `ip_unblocked` | Server → Client | IP was unblocked |

---

## Security Notes

> **WARNING:** This is a honeypot designed for controlled lab environments.

- The fake shell is **completely sandboxed** — it only returns hardcoded strings and never executes real commands
- The SSH server binds to port **2222** (not 22) to avoid conflicts with real SSH
- All data is stored **in-memory only** — nothing persists after restart
- Do **not** expose this to the public internet without proper firewall rules and network isolation
- For production honeypots, consider [Cowrie](https://github.com/cowrie/cowrie) or [Kippo](https://github.com/desaster/kippo)

---

## License

This project is for **educational and lab purposes only**. Use responsibly.
