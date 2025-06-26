#!/bin/bash
# Start VPP eBPF Firewall Backend

cd "$(dirname "$0")/backend"
source venv/bin/activate
python main.py
