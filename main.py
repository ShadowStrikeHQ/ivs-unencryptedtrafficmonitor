import argparse
import logging
import socket
import struct
import pcapy
from scapy.all import *

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
PROTOCOLS_TO_MONITOR = ['http', 'ftp', 'telnet']  # Protocols to look for
DEFAULT_INTERFACE = 'eth0' # Default network interface

def setup_argparse():
    """Sets up the command-line argument parser."""
    parser = argparse.ArgumentParser(description='Monitor network traffic for unencrypted protocols (HTTP, FTP, Telnet).')
    parser.add_argument('-i', '--interface', type=str, default=DEFAULT_INTERFACE,
                        help=f'Network interface to listen on (default: {DEFAULT_INTERFACE})')
    parser.add_argument('-l', '--log-file', type=str, default='ivs-UnencryptedTrafficMonitor.log',
                        help='Path to the log file (default: ivs-UnencryptedTrafficMonitor.log)')
    return parser.parse_args()

def is_protocol_present(payload, protocol):
    """Checks if the specified protocol is present in the payload (case-insensitive)."""
    try:
        payload_str = payload.decode('utf-8', errors='ignore').lower() # Attempt to decode as UTF-8
        return protocol in payload_str
    except UnicodeDecodeError:
        # Log the error and return False.  Some payloads might not be decodable.
        logging.debug(f"UnicodeDecodeError decoding payload, skipping {protocol} check.")
        return False

def process_packet(packet, interface):
    """Processes each captured packet to detect unencrypted protocols."""
    try:
        # Parse the packet using scapy
        ethernet_header = Ether(packet)

        # Check for IP packets (IPv4 or IPv6)
        if ethernet_header.type == 0x0800:  # IPv4
            ip_header = ethernet_header[IP]
            transport_layer = ip_header.payload

            # Check for TCP packets
            if transport_layer.name == "TCP":
                tcp_header = transport_layer
                payload = tcp_header.payload.original

                if payload:  # Only process packets with a payload
                    for protocol in PROTOCOLS_TO_MONITOR:
                        if is_protocol_present(payload, protocol):
                            logging.warning(f"Unencrypted {protocol.upper()} traffic detected on interface {interface}: "
                                             f"Source IP: {ip_header.src}, Port: {tcp_header.sport} -> "
                                             f"Destination IP: {ip_header.dst}, Port: {tcp_header.dport}")
                            break # Only report once per packet
        elif ethernet_header.type == 0x86DD: # IPv6
            ip_header = ethernet_header[IPv6]
            transport_layer = ip_header.payload

            # Check for TCP packets
            if transport_layer.name == "TCP":
                tcp_header = transport_layer
                payload = tcp_header.payload.original

                if payload:  # Only process packets with a payload
                    for protocol in PROTOCOLS_TO_MONITOR:
                        if is_protocol_present(payload, protocol):
                            logging.warning(f"Unencrypted {protocol.upper()} traffic detected on interface {interface}: "
                                             f"Source IP: {ip_header.src}, Port: {tcp_header.sport} -> "
                                             f"Destination IP: {ip_header.dst}, Port: {tcp_header.dport}")
                            break # Only report once per packet


    except Exception as e:
        logging.error(f"Error processing packet: {e}")


def main():
    """Main function to capture packets and analyze them."""
    args = setup_argparse()

    # Configure logging to file
    file_handler = logging.FileHandler(args.log_file)
    file_handler.setLevel(logging.WARNING)  # Only log warnings and errors to file
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    logging.getLogger('').addHandler(file_handler)

    interface = args.interface

    try:
        # Capture packets indefinitely
        sniff(iface=interface, prn=lambda pkt: process_packet(raw(pkt), interface), store=0)


    except pcapy.PcapError as e:
        logging.error(f"PcapError: {e}.  Ensure you have permission to access the network interface.")
    except socket.error as e:
        logging.error(f"Socket error: {e}.  Ensure the interface '{interface}' exists and you have permission to access it.")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    # Example Usage:
    # python ivs-UnencryptedTrafficMonitor.py -i eth0 -l traffic.log
    # This will monitor the eth0 interface and log warnings to traffic.log.
    main()