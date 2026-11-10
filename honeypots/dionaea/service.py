#!/usr/bin/env python3
"""
Dionaea Honeypot Multi-Service Trap (Apple Silicon Native & Standalone)
Emulates vulnerable protocols:
  - SMB (Port 4445 / 445) - MS17-010 EternalBlue / SMBv1 probes
  - HTTP (Port 8081 / 80) - Web exploit probes & directory traversal
  - FTP (Port 2121 / 21)  - Anonymous / credential brute-force traps
Captures payload metadata and records SHA-256 and MD5 checksums into dionaea.json.
"""

import asyncio
import datetime
import hashlib
import json
import os
import sys
import uuid

LOG_DIR = os.environ.get(
    "DIONAEA_LOG_DIR",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../infrastructure/docker/volumes/dionaea/log"))
)
LOG_FILE = os.path.join(LOG_DIR, "dionaea.json")
BINARIES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../infrastructure/docker/volumes/dionaea/binaries"))

SMB_PORT = int(os.environ.get("DIONAEA_SMB_PORT", 4445))
HTTP_PORT = int(os.environ.get("DIONAEA_HTTP_PORT", 8081))
FTP_PORT = int(os.environ.get("DIONAEA_FTP_PORT", 2121))

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(BINARIES_DIR, exist_ok=True)


def emit_event(event_dict: dict):
    """Appends structured JSON event to dionaea.json with ISO-8601 UTC timestamp."""
    event_dict["timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    line = json.dumps(event_dict) + "\n"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line)
        f.flush()
    sys.stdout.write(f"[DIONAEA] [{event_dict.get('service')}] {event_dict.get('event_type')}: {event_dict.get('message')}\n")
    sys.stdout.flush()


async def handle_http_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    src_ip = peer[0] if peer else "127.0.0.1"
    src_port = peer[1] if peer else 0
    conn_id = uuid.uuid4().hex[:8]

    try:
        request_line = await asyncio.wait_for(reader.readline(), timeout=10.0)
        req_str = request_line.decode("utf-8", errors="ignore").strip()

        headers = []
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=5.0)
            if not line or line in [b"\r\n", b"\n"]:
                break
            headers.append(line.decode("utf-8", errors="ignore").strip())

        parts = req_str.split()
        method = parts[0] if parts else "GET"
        path = parts[1] if len(parts) > 1 else "/"

        is_suspicious = any(p in path.lower() for p in ["..", "cmd", "etc/passwd", "win.ini", ".env", "shell", "eval"])

        emit_event({
            "service": "http",
            "connection_id": conn_id,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_port": HTTP_PORT,
            "event_type": "exploit_probe" if is_suspicious else "request",
            "method": method,
            "url": path,
            "headers": headers[:5],
            "severity": "HIGH" if is_suspicious else "LOW",
            "message": f"HTTP {method} {path} from {src_ip}:{src_port}"
        })

        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Server: Apache/2.4.41 (Ubuntu)\r\n"
            b"Content-Type: text/html\r\n"
            b"Content-Length: 45\r\n"
            b"Connection: close\r\n\r\n"
            b"<html><body><h1>Default Web Page</h1></body></html>"
        )
        writer.write(response)
        await writer.drain()

    except Exception:
        pass
    finally:
        writer.close()
        await writer.wait_closed()


async def handle_ftp_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    src_ip = peer[0] if peer else "127.0.0.1"
    src_port = peer[1] if peer else 0
    conn_id = uuid.uuid4().hex[:8]

    emit_event({
        "service": "ftp",
        "connection_id": conn_id,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_port": FTP_PORT,
        "event_type": "connect",
        "message": f"FTP connection from {src_ip}:{src_port}"
    })

    try:
        writer.write(b"220 ProFTPD 1.3.5 Server (Ubuntu) [127.0.0.1]\r\n")
        await writer.drain()

        user = ""
        while True:
            cmd_line = await asyncio.wait_for(reader.readline(), timeout=20.0)
            if not cmd_line:
                break
            cmd_str = cmd_line.decode("utf-8", errors="ignore").strip()
            parts = cmd_str.split(" ", 1)
            verb = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else ""

            if verb == "USER":
                user = arg
                writer.write(f"331 Password required for {user}\r\n".encode())
                await writer.drain()
            elif verb == "PASS":
                password = arg
                emit_event({
                    "service": "ftp",
                    "connection_id": conn_id,
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_port": FTP_PORT,
                    "event_type": "authentication",
                    "username": user,
                    "password": password,
                    "message": f"FTP login attempt: user '{user}' pass '{password}'"
                })
                writer.write(b"530 Login incorrect.\r\n")
                await writer.drain()
            elif verb in ["QUIT", "EXIT"]:
                writer.write(b"221 Goodbye.\r\n")
                await writer.drain()
                break
            else:
                writer.write(b"500 Unknown command.\r\n")
                await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()
        await writer.wait_closed()


async def handle_smb_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    src_ip = peer[0] if peer else "127.0.0.1"
    src_port = peer[1] if peer else 0
    conn_id = uuid.uuid4().hex[:8]

    emit_event({
        "service": "smb",
        "connection_id": conn_id,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_port": SMB_PORT,
        "event_type": "smb_probe",
        "severity": "HIGH",
        "message": f"SMB connection / EternalBlue exploit probe from {src_ip}:{src_port}"
    })

    try:
        data = await asyncio.wait_for(reader.read(1024), timeout=10.0)
        if data:
            # Simulate capturing shellcode payload or probe bytes
            sha256 = hashlib.sha256(data).hexdigest()
            md5 = hashlib.md5(data).hexdigest()
            emit_event({
                "service": "smb",
                "connection_id": conn_id,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_port": SMB_PORT,
                "event_type": "payload_capture",
                "sha256": sha256,
                "md5": md5,
                "payload_size": len(data),
                "severity": "CRITICAL",
                "message": f"Captured binary payload (SHA256: {sha256[:16]}...)"
            })
    except Exception:
        pass
    finally:
        writer.close()
        await writer.wait_closed()


async def main():
    print("[*] Starting Dionaea Honeypot Multi-Service Trap...")
    print(f"[*] SMB Trap Listening on 0.0.0.0:{SMB_PORT}")
    print(f"[*] HTTP Trap Listening on 0.0.0.0:{HTTP_PORT}")
    print(f"[*] FTP Trap Listening on 0.0.0.0:{FTP_PORT}")
    print(f"[*] Logging structured JSON to: {LOG_FILE}")

    srv_smb = await asyncio.start_server(handle_smb_client, "0.0.0.0", SMB_PORT)
    srv_http = await asyncio.start_server(handle_http_client, "0.0.0.0", HTTP_PORT)
    srv_ftp = await asyncio.start_server(handle_ftp_client, "0.0.0.0", FTP_PORT)

    async with srv_smb, srv_http, srv_ftp:
        await asyncio.gather(
            srv_smb.serve_forever(),
            srv_http.serve_forever(),
            srv_ftp.serve_forever()
        )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] Dionaea trap stopped.")

