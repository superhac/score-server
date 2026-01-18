#!/usr/bin/env python3
"""
UDP Score Server Test Client

This script listens for UDP messages from the VPinball ScoreServer plugin
and displays them in a formatted way.

Usage:
    python3 test-udp.py [port]

Default port: 9000
"""

import socket
import json
import sys
from datetime import datetime

def format_timestamp(iso_timestamp):
    """Convert ISO timestamp to local time"""
    try:
        dt = datetime.fromisoformat(iso_timestamp.replace('Z', '+00:00'))
        return dt.strftime('%H:%M:%S.%f')[:-3]
    except:
        return iso_timestamp

def print_message(data, addr):
    """Pretty print a score message"""
    msg_type = data.get('type', 'unknown')
    timestamp = format_timestamp(data.get('timestamp', ''))
    rom = data.get('rom', 'Unknown')
    machine_id = data.get('machine_id', '')

    # Build header with machine ID if present
    header = f"[{timestamp}]"
    if machine_id:
        header += f" [{machine_id}]"
    header += f" {rom}"

    print("\n" + "="*80)

    if msg_type == 'game_start':
        print(f"{header} - GAME START")
        print("="*80)

    elif msg_type == 'game_end':
        print(f"{header} - GAME END")
        print("="*80)

    elif msg_type == 'high_scores':
        print(f"{header} - HIGH SCORES")
        print("="*80)
        scores = data.get('scores', [])
        if scores:
            max_label_len = max(len(s.get('label', '')) for s in scores)
            for score_entry in scores:
                label = score_entry.get('label', '').ljust(max_label_len)
                initials = score_entry.get('initials', '').rjust(3)
                score = score_entry.get('score', '').rjust(15)
                print(f"  {label}  {initials}  {score}")
        else:
            print("  (No scores)")

    elif msg_type == 'current_scores':
        players = data.get('players', 0)
        current_player = data.get('current_player', 0)
        current_ball = data.get('current_ball', 0)

        print(f"{header} - CURRENT SCORES")
        print(f"  Players: {players} | Current: Player {current_player} | Ball: {current_ball}")
        print("-"*80)

        scores = data.get('scores', [])
        if scores:
            for score_entry in scores:
                player = score_entry.get('player', 'Unknown')
                score = score_entry.get('score', '0').rjust(15)
                marker = " <-- PLAYING" if score_entry.get('player', '') == f"Player {current_player}" else ""
                print(f"  {player}: {score}{marker}")
        else:
            print("  (No scores)")

    elif msg_type == 'badge':
        player = data.get('player', 'Unknown')
        name = data.get('name', 'Unknown Achievement')
        description = data.get('description', '')

        print(f"{header} - ACHIEVEMENT UNLOCKED!")
        print("="*80)
        print(f"  🏆 {player}: {name}")
        if description:
            print(f"     {description}")

    else:
        print(f"{header} - UNKNOWN MESSAGE TYPE: {msg_type}")
        print("="*80)
        print(json.dumps(data, indent=2))

    print(f"\nReceived from {addr[0]}:{addr[1]} ({len(str(data))} bytes)")

def main():
    # Get port from command line or use default
    port = 9000
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print(f"Error: Invalid port number '{sys.argv[1]}'")
            sys.exit(1)

    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', port))

    print("="*80)
    print(f"VPinball Score Server - UDP Test Client")
    print("="*80)
    print(f"Listening on: 0.0.0.0:{port}")
    print(f"Waiting for messages from ScoreServer plugin...")
    print("\nConfigure VPinballX.ini with:")
    print(f"  [Plugin.ScoreServer]")
    print(f"  Enable = 1")
    print(f"  BroadcastMode = UDP")
    print(f"  UdpHost = <this-machine-ip>")
    print(f"  UdpPort = {port}")
    print("\nPress Ctrl+C to exit")
    print("="*80)

    message_count = 0

    try:
        while True:
            # Receive UDP packet
            data, addr = sock.recvfrom(65535)
            message_count += 1

            # Parse JSON
            try:
                message = json.loads(data.decode('utf-8'))
                print_message(message, addr)
            except json.JSONDecodeError as e:
                print(f"\n[ERROR] Failed to parse JSON from {addr[0]}:{addr[1]}")
                print(f"  Error: {e}")
                print(f"  Raw data: {data.decode('utf-8', errors='replace')}")
            except Exception as e:
                print(f"\n[ERROR] Unexpected error: {e}")
                print(f"  Raw data: {data.decode('utf-8', errors='replace')}")

    except KeyboardInterrupt:
        print("\n\n" + "="*80)
        print(f"Shutting down... (received {message_count} messages)")
        print("="*80)

    finally:
        sock.close()

if __name__ == '__main__':
    main()
