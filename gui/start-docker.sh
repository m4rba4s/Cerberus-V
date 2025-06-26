#!/bin/bash
# Start VPP eBPF Firewall GUI Stack with Docker

cd "$(dirname "$0")/docker"
docker-compose up -d
