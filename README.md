![C++](https://img.shields.io/badge/C%2B%2B-17-blue?style=flat&logo=cplusplus) ![CMake](https://img.shields.io/badge/CMake-3.20%2B-064F8C?style=flat&logo=cmake) ![Linux](https://img.shields.io/badge/Linux-Only-FCC624?style=flat&logo=linux&logoColor=black) ![GoogleTest](https://img.shields.io/badge/GoogleTest-150%2B%20tests-4285F4?style=flat&logo=google) [![CI/CD](https://github.com/IRomanchuk06/traffic_capture/workflows/CI%2FCD%20Pipeline/badge.svg)](https://github.com/IRomanchuk06/traffic_capture/actions) ![License](https://img.shields.io/badge/License-MIT-green?style=flat)
# Traffic Capture

**Traffic Capture** is a lightweight C++17 tool for capturing, parsing, and exporting network packets (Ethernet, ARP, IPv4) to PCAP format for analysis in Wireshark.
It features a **modular and extensible architecture**, where capture sources, protocol parsers, and exporters are independent, interchangeable components.

The project demonstrates a clean packet-processing pipeline designed for **scalability and easy integration** with custom network monitoring or analysis systems.

---

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Quickstart](#quickstart)
4. [Requirements](#requirements)
5. [Build and Run](#build-and-run)
6. [Testing](#testing)
7. [Project Structure](#project-structure)
8. [Code Quality](#code-quality)
9. [CI/CD](#cicd)
10. [Known Limitations](#known-limitations)
11. [Roadmap](#roadmap)
12. [License](#license)

---

## Overview

Traffic Capture provides a complete low-level packet processing pipeline:

1. Capture packets directly from a network interface using **raw sockets**
2. Parse Layer 2 (Ethernet, ARP) and Layer 3 (IPv4) headers
3. Display parsed packet details to **console** and export to **Wireshark-compatible PCAP files**
4. Provide a **modular API** for extending capture sources, parsers, and exporters

Its core design focuses on **extensibility, clarity, and modularity**, allowing new protocols or export formats to be added with minimal effort.

---

## Features

* Real-time packet capture from any interface
* Parsing of Ethernet, ARP, and IPv4 protocols
* PCAP export compatible with Wireshark and tcpdump
* Interactive command-line interface (CLI)
* Promiscuous mode support
* 150+ unit and integration tests (veth-based)
* Modular architecture for independent component development
* CI/CD with build, tests, static analysis, and formatting checks

---

## Quickstart

Clone and build:

```bash
git clone https://github.com/IRomanchuk06/traffic_capture.git
cd traffic_capture

sudo apt-get update
sudo apt-get install -y build-essential cmake ninja-build clang

cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Run interactively:

```bash
sudo ./bin/traffic_capture
```

Capture 100 packets and export to PCAP:

```bash
sudo ./bin/traffic_capture -i eth0 -c 100 -o packets.pcap
```

Capture for 30 seconds in promiscuous mode:

```bash
sudo ./bin/traffic_capture -i eth0 -t 30 -p
```

Open the resulting file in Wireshark:

```bash
wireshark packets.pcap
```

---

## Requirements

* Linux kernel **3.10+**
* **Root privileges** (required for raw sockets)
* **C++17** compiler (GCC 7+ / Clang 5+)
* **CMake 3.20+**, **Ninja** or **Make**

Optional development tools:

```bash
sudo apt-get install -y clang-tidy cppcheck clang-format
```

---

## Build and Run

Build with tests:

```bash
rm -rf build
cmake -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON
cmake --build build
```

Run tests:

```bash
cd build
ctest --output-on-failure
# sudo ctest --output-on-failure  # for integration tests
cd ..
```

CLI options:

```
-h, --help               Show help and exit
-i, --interface IFACE    Network interface to capture from
-c, --count N            Number of packets to capture
-t, --time SECS          Capture duration in seconds
-o, --output FILE        Output PCAP file (default: capture.pcap)
-p, --promiscuous        Enable promiscuous mode
-I, --interactive        Enable interactive mode (default)
-v, --verbose            Verbose output
-x, --hex                Print packets in hexadecimal format
-P, --parsed             Display parsed protocol information
```

---

## Testing

All tests (unit + integration):

```bash
cd build
sudo ctest --output-on-failure
cd ..
```

Unit tests only:

```bash
cd build
ctest -L unit --output-on-failure
cd ..
```

Integration tests (require sudo):

```bash
cd build
sudo ctest -L integration --output-on-failure
cd ..
```

Run a specific test:

```bash
cd build
sudo ctest -R "ArpParserTest.PacketTooShort27Bytes" --output-on-failure
cd ..
```

Notes:

* Loopback-based tests can be unstable in CI; use **veth pairs** instead.
* Integration tests are optional in CI (non-blocking).

---

## Project Structure

```
traffic_capture/
├─ src/
│  ├─ main.cpp              # Entry point (CLI)
│  ├─ capture.cpp           # Packet capture (raw sockets)
│  ├─ cli.cpp               # Interactive CLI and arguments
│  ├─ export/pcap.cpp       # PCAP exporter
│  └─ parsers/
│     ├─ frame.cpp          # Ethernet parser
│     ├─ L2/arp.cpp         # ARP parser
│     └─ L3/ipv4.cpp        # IPv4 parser
├─ h/
│  ├─ capture.hpp
│  ├─ cli.hpp
│  └─ parsers/...
├─ tests/
│  ├─ unit/                 # Unit tests
│  └─ integration/          # Integration (veth)
│     ├─ test_real_capture.cpp
│     └─ helpers/
│        ├─ veth_setup.hpp
│        └─ packet_sender.hpp
├─ .github/workflows/ci.yml # CI/CD configuration
├─ .clang-tidy
├─ .clang-format
└─ README.md
```

---

## Code Quality

Run local checks:

```bash
./run_checks.sh
```

Includes:

* Static analysis (`clang-tidy`, `cppcheck`)
* Formatting verification (`clang-format`)
* Build validation and test execution

Also included is a script to auto-format project code using `clang-format`:

```bash
./format_code.sh
```

This script recursively formats C++ source and header files in `src/`, `h/`, and `tests/` directories according to the project style.

---

## CI/CD

GitHub Actions perform:

* Build and run of unit tests
* Integration tests (optional, sudo required)
* Static analysis (`clang-tidy`, `cppcheck`)
* Code formatting validation (non-blocking)

CI status:

[![CI/CD Status](https://github.com/IRomanchuk06/traffic_capture/workflows/CI%2FCD%20Pipeline/badge.svg)](https://github.com/IRomanchuk06/traffic_capture/actions)

---

## Known Limitations

* Requires root privileges for raw socket access
* Loopback testing may fail in CI environments
* Supported on **Linux only**

---

## Roadmap

* Extended protocol support (IPv6, ICMP, TCP, UDP)
* BPF-style filtering
* Interface statistics and live metrics
* GUI / web dashboard
* Performance benchmarking suite

---

## License

This project is licensed under the **MIT License**.  
You are free to use, modify, and distribute this software with attribution.

See the full license text in the [LICENSE](LICENSE) file.

