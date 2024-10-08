# Packet Capture Tool

This Python script captures and analyzes network packets using raw sockets. It parses Ethernet, IPv4, and TCP headers from captured packets and prints the details to the console.

## Features

- **Ethernet Frame Parsing**: Extracts and prints destination and source MAC addresses, as well as the Ethernet frame protocol.
- **IPv4 Packet Parsing**: Extracts and prints IPv4 header details, including version, header length, TTL, protocol, source, and destination IP addresses.
- **TCP Segment Parsing**: Extracts and prints TCP header details, including source and destination ports, sequence and acknowledgment numbers, and TCP flags.

## Requirements

- Python 3.x
- Administrative or root privileges (required for raw socket operations)

## Installation

1. Ensure you have Python 3.x installed.
2. Save the provided script to a file, e.g., `packet_capture.py`.

## Usage

1. Open a terminal with administrative or root privileges.
2. Run the script with Python:

    ```sh
    sudo python3 packet_capture.py
    ```

3. The script will start capturing packets and print details about Ethernet frames, IPv4 packets, and TCP segments.

## Code Explanation

1. **`get_mac_addr(mac_bytes)`**: Converts raw MAC address bytes to a human-readable string format.
2. **`ethernet_head(raw_data)`**: Parses the Ethernet header from raw packet data.
3. **`get_ip(addr)`**: Converts raw IP address bytes to a human-readable string format.
4. **`ipv4_headers(raw_data)`**: Parses the IPv4 header from raw packet data.
5. **`tcp_head(raw_data)`**: Parses the TCP header from raw packet data.
6. **`main()`**: Initializes the raw socket, captures packets in an infinite loop, and parses them using the above functions.

## Notes

- The script captures all traffic on the network interface to which it is bound. Ensure proper permissions and use it responsibly.
- Raw sockets are used, so administrative or root privileges are necessary to execute this script.
