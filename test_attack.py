"""Simulate a realistic attack sequence against the honeypot for demo purposes."""
import paramiko
import time
import sys

TARGET = "127.0.0.1"
PORT = 2222

# Phase 1: Brute-force attempts (failed logins)
print("[*] Phase 1: Brute-force login attempts...")
brute_creds = [
    ("root", "password"),
    ("root", "123456"),
    ("admin", "admin123"),
    ("root", "toor"),
    ("ubuntu", "password"),
    ("test", "test123"),
    ("mysql", "mysql"),
    ("postgres", "postgres"),
    ("root", "qwerty"),
    ("root", "letmein"),
    ("admin", "password"),
    ("guest", "guest"),
]

for user, pwd in brute_creds:
    try:
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(TARGET, port=PORT, username=user, password=pwd, timeout=5, banner_timeout=5, auth_timeout=5)
        print(f"  [+] SUCCESS: {user}:{pwd}")
        c.close()
    except paramiko.AuthenticationException:
        print(f"  [-] FAILED:  {user}:{pwd}")
    except Exception as e:
        print(f"  [!] ERROR:   {user}:{pwd} -> {e}")
    time.sleep(0.2)

# Phase 2: Successful login + run commands
print("\n[*] Phase 2: Successful login + command execution...")
try:
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(TARGET, port=PORT, username="root", password="root", timeout=5, banner_timeout=5, auth_timeout=5)
    print(f"  [+] Logged in as root:root")

    commands = ["whoami", "id", "uname -a", "cat /etc/passwd", "ls -la", "ps aux", "netstat -tlnp", "cat .bash_history"]
    for cmd in commands:
        stdin, stdout, stderr = c.exec_command(cmd)
        output = stdout.read().decode().strip()
        print(f"  CMD: {cmd}")
        if output:
            for line in output.split('\n')[:3]:
                print(f"       {line}")
        time.sleep(0.3)

    c.close()
    print("  [+] Session closed")
except Exception as e:
    print(f"  [!] Session error: {e}")

print("\n[*] Attack simulation complete!")
