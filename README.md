# WiFi Deauthentication Research Tool (C++)

## Overview
This project demonstrates how WiFi deauthentication frames are constructed, transmitted, and managed using low-level packet injection in C++ with libpcap.

It includes interface discovery, monitor mode setup, packet crafting, rate control, and runtime statistics.

## Features

- WiFi interface discovery
- Monitor mode configuration
- Deauthentication frame crafting (802.11)
- Packet injection using libpcap
- Configurable packets-per-second (PPS)
- Broadcast and targeted modes
- Real-time statistics display
- Attack reporting system

## Technical Concepts

- RadioTap headers
- IEEE 802.11 management frames
- Packet injection
- Wireless interface control
- Timing and rate limiting

## Requirements

- Linux system (Kali / Ubuntu recommended)
- Wireless adapter with monitor mode support
- libpcap

Install dependencies:

```bash
sudo apt install libpcap-dev
Compilation
g++ src/deauth.cpp -o deauth -lpcap
Usage
sudo ./deauth

Steps:

Select WiFi interface
Tool enables monitor mode
Enter target AP MAC or use SCAN
Configure PPS and duration
Start simulation
Output
Real-time attack statistics
Packet transmission metrics
Generated report file after execution
⚠️ Disclaimer

This project is developed strictly for educational and cybersecurity research purposes.

Do NOT use on networks without explicit authorization.

The author is not responsible for misuse.

Learning Outcomes
Understanding WiFi deauthentication mechanisms
Working with raw packets using libpcap
Wireless network behavior analysis
Performance and rate control in packet transmission
Author

¬Muhammad Arslan