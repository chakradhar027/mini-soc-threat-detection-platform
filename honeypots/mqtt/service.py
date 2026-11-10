#!/usr/bin/env python3
"""
MQTT Honeypot Broker & Monitoring Trap Service (Apple Silicon Native & Standalone)
Listens on configured MQTT honeypot port (18883 / 1883).
Captures rogue connections, wildcard subscriptions (#), unauthorized command publishes,
and authentication attacks against IoT control planes.
Logs structured JSON events directly to mqtt_honey.json.
"""

import asyncio
import datetime
import json
import os
import struct
import sys
import uuid

LOG_DIR = os.environ.get(
    "MOSQUITTO_LOG_DIR",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../infrastructure/docker/volumes/mosquitto/log"))
)
LOG_FILE = os.path.join(LOG_DIR, "mqtt_honey.json")
MQTT_HONEY_PORT = int(os.environ.get("MOSQUITTO_HONEY_PORT", 18883))

os.makedirs(LOG_DIR, exist_ok=True)


def emit_event(event_dict: dict):
    """Appends structured JSON event to mqtt_honey.json with ISO-8601 UTC timestamp."""
    event_dict["timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    event_dict["source_service"] = "mqtt_honeypot"
    line = json.dumps(event_dict) + "\n"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line)
        f.flush()
    sys.stdout.write(f"[MQTT-HONEY] [{event_dict.get('event_type')}] {event_dict.get('message')}\n")
    sys.stdout.flush()


def parse_remaining_length(data: bytes, offset: int = 1):
    multiplier = 1
    value = 0
    idx = offset
    while True:
        if idx >= len(data):
            return 0, idx
        digit = data[idx]
        value += (digit & 127) * multiplier
        multiplier *= 128
        idx += 1
        if (digit & 128) == 0:
            break
    return value, idx


async def handle_mqtt_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    src_ip = peer[0] if peer else "127.0.0.1"
    src_port = peer[1] if peer else 0
    session_id = uuid.uuid4().hex[:8]
    client_id = "unknown"

    emit_event({
        "event_type": "connect_attempt",
        "session_id": session_id,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_port": MQTT_HONEY_PORT,
        "severity": "LOW",
        "message": f"TCP connection from {src_ip}:{src_port} to MQTT Honeypot"
    })

    try:
        while True:
            header_byte = await reader.read(1)
            if not header_byte:
                break
            packet_type = header_byte[0] >> 4

            # Read remaining length
            len_bytes = bytearray()
            multiplier = 1
            rem_len = 0
            while True:
                b = await reader.read(1)
                if not b:
                    break
                digit = b[0]
                rem_len += (digit & 127) * multiplier
                multiplier *= 128
                if (digit & 128) == 0:
                    break

            payload = await reader.readexactly(rem_len) if rem_len > 0 else b""

            # Packet 1: CONNECT
            if packet_type == 1:
                # Parse protocol name, flags, client id
                try:
                    proto_len = struct.unpack("!H", payload[0:2])[0]
                    proto_name = payload[2:2+proto_len].decode("utf-8", errors="ignore")
                    offset = 2 + proto_len + 1 # + version
                    flags = payload[offset]
                    offset += 1 + 2 # + keepalive
                    cid_len = struct.unpack("!H", payload[offset:offset+2])[0]
                    offset += 2
                    client_id = payload[offset:offset+cid_len].decode("utf-8", errors="ignore")
                    offset += cid_len

                    user = None
                    password = None
                    if flags & 0x80: # Username flag
                        u_len = struct.unpack("!H", payload[offset:offset+2])[0]
                        offset += 2
                        user = payload[offset:offset+u_len].decode("utf-8", errors="ignore")
                        offset += u_len
                    if flags & 0x40: # Password flag
                        p_len = struct.unpack("!H", payload[offset:offset+2])[0]
                        offset += 2
                        password = payload[offset:offset+p_len].decode("utf-8", errors="ignore")
                        offset += p_len

                    is_probe = client_id.startswith(("scanner", "shodan", "censys", "test", "admin"))
                    emit_event({
                        "event_type": "mqtt_connect",
                        "session_id": session_id,
                        "client_id": client_id,
                        "username": user,
                        "password": password,
                        "src_ip": src_ip,
                        "src_port": src_port,
                        "dst_port": MQTT_HONEY_PORT,
                        "protocol": proto_name,
                        "severity": "MEDIUM" if is_probe or password else "LOW",
                        "message": f"MQTT CONNECT from client_id='{client_id}', user='{user}'"
                    })
                except Exception as e:
                    emit_event({
                        "event_type": "malformed_packet",
                        "src_ip": src_ip,
                        "session_id": session_id,
                        "message": f"Malformed MQTT CONNECT: {str(e)}"
                    })

                # Respond with CONNACK (0x20, 0x02, 0x00, 0x00 - Accepted)
                writer.write(bytes([0x20, 0x02, 0x00, 0x00]))
                await writer.drain()

            # Packet 3: PUBLISH
            elif packet_type == 3:
                try:
                    topic_len = struct.unpack("!H", payload[0:2])[0]
                    topic = payload[2:2+topic_len].decode("utf-8", errors="ignore")
                    content = payload[2+topic_len:].decode("utf-8", errors="ignore")

                    is_tampering = any(k in topic for k in ["control", "admin", "cmd", "actuator", "update"])
                    emit_event({
                        "event_type": "unauthorized_publish" if is_tampering else "mqtt_publish",
                        "session_id": session_id,
                        "client_id": client_id,
                        "src_ip": src_ip,
                        "src_port": src_port,
                        "dst_port": MQTT_HONEY_PORT,
                        "topic": topic,
                        "payload": content[:200],
                        "severity": "HIGH" if is_tampering else "LOW",
                        "message": f"PUBLISH to topic='{topic}': {content[:80]}"
                    })
                except Exception:
                    pass

            # Packet 8: SUBSCRIBE
            elif packet_type == 8:
                try:
                    msg_id = struct.unpack("!H", payload[0:2])[0]
                    offset = 2
                    topics = []
                    while offset < len(payload):
                        t_len = struct.unpack("!H", payload[offset:offset+2])[0]
                        offset += 2
                        sub_topic = payload[offset:offset+t_len].decode("utf-8", errors="ignore")
                        offset += t_len + 1 # + qos
                        topics.append(sub_topic)

                    has_wildcard = any("#" in t or "+" in t for t in topics)
                    emit_event({
                        "event_type": "wildcard_subscription" if has_wildcard else "mqtt_subscribe",
                        "session_id": session_id,
                        "client_id": client_id,
                        "src_ip": src_ip,
                        "src_port": src_port,
                        "dst_port": MQTT_HONEY_PORT,
                        "topics": topics,
                        "severity": "HIGH" if has_wildcard else "LOW",
                        "message": f"SUBSCRIBE request for topics={topics} (Wildcard: {has_wildcard})"
                    })

                    # Send SUBACK (0x90, 0x03, msg_id_h, msg_id_l, 0x00)
                    suback = bytearray([0x90, 0x03, payload[0], payload[1], 0x00])
                    writer.write(suback)
                    await writer.drain()
                except Exception:
                    pass

            # Packet 12: PINGREQ
            elif packet_type == 12:
                # PINGRESP (0xD0, 0x00)
                writer.write(bytes([0xD0, 0x00]))
                await writer.drain()

            # Packet 14: DISCONNECT
            elif packet_type == 14:
                break

    except Exception:
        pass
    finally:
        emit_event({
            "event_type": "disconnect",
            "session_id": session_id,
            "client_id": client_id,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_port": MQTT_HONEY_PORT,
            "message": f"MQTT client disconnected: {src_ip}:{src_port}"
        })
        writer.close()
        await writer.wait_closed()


async def main():
    print("[*] Starting Mosquitto/Python MQTT Honeypot Service...")
    print(f"[*] MQTT Trap Listening on 0.0.0.0:{MQTT_HONEY_PORT}")
    print(f"[*] Logging structured JSON to: {LOG_FILE}")

    server = await asyncio.start_server(handle_mqtt_client, "0.0.0.0", MQTT_HONEY_PORT)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] MQTT Honeypot stopped.")

