#!/usr/bin/env python3
"""
Cowrie Honeypot Emulation Service (Apple Silicon Native & Standalone)
Listens on configured SSH (2222) and Telnet (2223) ports.
Captures brute-force credentials, commands, and session metadata.
Emits structured JSON logs strictly adhering to the Cowrie log format.
"""

import asyncio
import datetime
import hashlib
import json
import os
import sys
import uuid

LOG_DIR = os.environ.get(
    "COWRIE_LOG_DIR",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../infrastructure/docker/volumes/cowrie/log"))
)
LOG_FILE = os.path.join(LOG_DIR, "cowrie.json")
DOWNLOAD_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../infrastructure/docker/volumes/cowrie/downloads"))

SSH_PORT = int(os.environ.get("COWRIE_SSH_PORT", 2222))
TELNET_PORT = int(os.environ.get("COWRIE_TELNET_PORT", 2223))

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(DOWNLOAD_DIR, exist_ok=True)


def emit_event(event_dict: dict):
    """Appends structured JSON event to cowrie.json with ISO-8601 UTC timestamp."""
    event_dict["timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    event_dict["system"] = "srv-prod-gateway01"
    line = json.dumps(event_dict) + "\n"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line)
        f.flush()
    sys.stdout.write(f"[COWRIE] [{event_dict.get('eventid')}] {event_dict.get('message')}\n")
    sys.stdout.flush()


async def handle_telnet_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    src_ip = peer[0] if peer else "127.0.0.1"
    src_port = peer[1] if peer else 0
    session_id = uuid.uuid4().hex[:12]

    emit_event({
        "eventid": "cowrie.session.connect",
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_port": TELNET_PORT,
        "session": session_id,
        "protocol": "telnet",
        "message": f"New connection: {src_ip}:{src_port} (session {session_id}) on port {TELNET_PORT}"
    })

    try:
        writer.write(b"Ubuntu 22.04.3 LTS\r\nsrv-prod-gateway01 login: ")
        await writer.drain()

        login_line = await asyncio.wait_for(reader.readline(), timeout=30.0)
        username = login_line.decode("utf-8", errors="ignore").strip()

        writer.write(b"Password: ")
        await writer.drain()

        pass_line = await asyncio.wait_for(reader.readline(), timeout=30.0)
        password = pass_line.decode("utf-8", errors="ignore").strip()

        # Check authentication (accept common root / admin backdoor for honey interaction)
        is_success = (username in ["root", "admin", "ubuntu"] and password in ["admin", "root", "123456", "password"])

        if is_success:
            emit_event({
                "eventid": "cowrie.login.success",
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_port": TELNET_PORT,
                "session": session_id,
                "username": username,
                "password": password,
                "message": f"login attempt [{username}/{password}] succeeded"
            })

            writer.write(b"\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)\r\n")
            writer.write(b"root@srv-prod-gateway01:~# ")
            await writer.drain()

            while True:
                cmd_line = await asyncio.wait_for(reader.readline(), timeout=60.0)
                if not cmd_line:
                    break
                command = cmd_line.decode("utf-8", errors="ignore").strip()
                if not command:
                    writer.write(b"root@srv-prod-gateway01:~# ")
                    await writer.drain()
                    continue

                if command in ["exit", "logout", "quit"]:
                    break

                emit_event({
                    "eventid": "cowrie.command.input",
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_port": TELNET_PORT,
                    "session": session_id,
                    "input": command,
                    "message": f"CMD: {command}"
                })

                # Check if command is a simulated payload download (wget / curl)
                if any(k in command for k in ["wget", "curl"]):
                    parts = command.split()
                    url = parts[-1] if len(parts) > 1 else "http://malicious.payload/bin.sh"
                    fake_hash = hashlib.sha256(command.encode()).hexdigest()
                    emit_event({
                        "eventid": "cowrie.session.file_download",
                        "src_ip": src_ip,
                        "src_port": src_port,
                        "dst_port": TELNET_PORT,
                        "session": session_id,
                        "url": url,
                        "shasum": fake_hash,
                        "message": f"Downloaded URL [{url}] to downloads/{fake_hash}"
                    })
                    writer.write(b"Saving to: 'payload.sh' [100%]\r\n")

                if command == "uname -a":
                    writer.write(b"Linux srv-prod-gateway01 5.15.0-88-generic #98-Ubuntu SMP Mon Oct 2 15:18:56 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\r\n")
                elif command == "whoami":
                    writer.write(b"root\r\n")
                elif command == "id":
                    writer.write(b"uid=0(root) gid=0(root) groups=0(root)\r\n")
                else:
                    writer.write(f"{command}: command not found\r\n".encode())

                writer.write(b"root@srv-prod-gateway01:~# ")
                await writer.drain()
        else:
            emit_event({
                "eventid": "cowrie.login.failed",
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_port": TELNET_PORT,
                "session": session_id,
                "username": username,
                "password": password,
                "message": f"login attempt [{username}/{password}] failed"
            })
            writer.write(b"\r\nLogin incorrect\r\n")
            await writer.drain()

    except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
        pass
    finally:
        emit_event({
            "eventid": "cowrie.session.closed",
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_port": TELNET_PORT,
            "session": session_id,
            "message": f"Connection lost: {src_ip}:{src_port}"
        })
        writer.close()
        await writer.wait_closed()


async def handle_ssh_banner(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    src_ip = peer[0] if peer else "127.0.0.1"
    src_port = peer[1] if peer else 0
    session_id = uuid.uuid4().hex[:12]

    emit_event({
        "eventid": "cowrie.session.connect",
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_port": SSH_PORT,
        "session": session_id,
        "protocol": "ssh",
        "message": f"New connection: {src_ip}:{src_port} (session {session_id}) on port {SSH_PORT}"
    })

    try:
        # Send SSH banner
        writer.write(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
        await writer.drain()

        client_banner = await asyncio.wait_for(reader.readline(), timeout=10.0)
        client_version = client_banner.decode("utf-8", errors="ignore").strip()

        emit_event({
            "eventid": "cowrie.client.version",
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_port": SSH_PORT,
            "session": session_id,
            "version": client_version,
            "message": f"Remote SSH version: {client_version}"
        })

        # Process SSH authentication probe or credential exchange
        try:
            auth_payload = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            username = "guest"
            password = "wrongpassword"
            if auth_payload and b":" in auth_payload:
                try:
                    parts = auth_payload.decode("utf-8", errors="ignore").strip().split(":", 1)
                    username = parts[0]
                    password = parts[1]
                except Exception:
                    pass
            elif auth_payload:
                username = "ssh_probe"
                password = "bad_password"

            emit_event({
                "eventid": "cowrie.login.failed",
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_port": SSH_PORT,
                "session": session_id,
                "username": username,
                "password": password,
                "message": f"login attempt [{username}/{password}] failed"
            })
        except asyncio.TimeoutError:
            pass
    except Exception:
        pass
    finally:
        emit_event({
            "eventid": "cowrie.session.closed",
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_port": SSH_PORT,
            "session": session_id,
            "message": f"Connection lost: {src_ip}:{src_port}"
        })
        writer.close()
        await writer.wait_closed()


async def main():
    print(f"[*] Starting Cowrie Honeypot Emulation Service...")
    print(f"[*] SSH Listening on 0.0.0.0:{SSH_PORT}")
    print(f"[*] Telnet Listening on 0.0.0.0:{TELNET_PORT}")
    print(f"[*] Logging structured JSON to: {LOG_FILE}")

    server_telnet = await asyncio.start_server(handle_telnet_client, "0.0.0.0", TELNET_PORT)
    server_ssh = await asyncio.start_server(handle_ssh_banner, "0.0.0.0", SSH_PORT)

    async with server_telnet, server_ssh:
        await asyncio.gather(server_telnet.serve_forever(), server_ssh.serve_forever())


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] Cowrie service stopped.")

