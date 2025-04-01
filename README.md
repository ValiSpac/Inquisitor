# Inquisitor - ARP Poisoning & FTP Sniffer

## Overview
**Inquisitor** is a tool for ARP poisoning (MITM attack) and FTP traffic sniffing. It captures FTP file transfers and login attempts in real time.

## Features
- **ARP Poisoning** (Full-duplex attack)
- **FTP Sniffing** (Detects file transfers & credentials)
- **Automatic Cleanup** (Restores ARP tables on exit)
- **Runs in Docker** (Easy setup with `docker-compose`)

## Installation
### Prerequisites
- Linux, Docker, Python 3
- Install dependencies:
  ```sh
  make
  ```

### Start/Stop Environment
- Start: `make up-no-detached`
- Stop: `make down`
- Clean: `make clean`

## Usage
Run with `sudo`:
```sh
source venv/bin/activate
sudo python inquisitor.py <IP-src> <MAC-src> <IP-target> <MAC-target> <interface> [-v]
```

### Example
```sh
sudo python inquisitor.py 192.168.1.10 00:11:22:33:44:55 192.168.1.20 66:77:88:99:AA:BB eth0 -v
```

Press `CTRL+C` to stop and restore ARP tables.
