# C-Packet-Capture

A lightweight, low-level network packet sniffer written in C using raw sockets.

This project demonstrates how to capture and inspect Ethernet frames and transport-layer packets (IP/TCP/UDP) directly from the network interface using Linux raw sockets (AF_PACKET). It was developed in WSL (Ubuntu) but is intended to run on Linux environments where raw socket access is available.

Why this project?
- Learn how packets flow from the NIC up the stack by observing Ethernet, IP, TCP and UDP headers.
- Understand raw sockets, packet capture fundamentals, and how to parse headers in C.
- Minimal, educational codebase you can extend to add filtering, logging, or PCAP export.

Quick features (planned / in-progress):
- Capture all link-layer traffic with AF_PACKET and ETH_P_ALL.
- Parse and pretty-print Ethernet, IPv4, TCP and UDP headers.
- Optionally log output to a file and support simple filters (IP, port, protocol).

Build

This is a plain C program — compile with gcc:

```bash
gcc -o sniffer sniffer.c
```

Run

Root privileges are required to open raw sockets. Either run as root, or run using sudo:

```bash
sudo ./sniffer
```

Notes & next steps
- The current codebase is small and intended as a learning project. Expect to add argument parsing, robust error handling, and a packet processing loop.
- Consider exporting captured packets to a PCAP file or integrating with libpcap for more features.

License

Use and modify freely for learning and experimentation.
