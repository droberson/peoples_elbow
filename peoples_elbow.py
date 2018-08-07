#!/usr/bin/env python3

""" peoples_elbow.py -- by Daniel Roberson @dmfroberson

This shows unique TCP, UDP, and ICMP flows within a given timeframe. For
example, if you visit Google 100 times per hour and your observed time is set
to one hour, you will see it only once.

This is meant to filter out noise when observing network traffic, letting an
analyst focus on outliers.


prereqs:

mmh3 (not actually required, but helps for speed)
pcapy

TODO:
    - argparse
      - interface
      - bpf filter
      - bloom filter size/times
      - disable color
    - daemonize
    - output strategy
      - syslog
      - logfile
      - json
"""

import socket

from time import time, ctime
from fcntl import ioctl
from struct import pack, unpack
from os import readlink
from glob import glob
from ipaddress import ip_address

import pcapy

from timingbloomfilter import TimingBloomFilter


class Color():
    """Color class - Handle colors on the terminal."""
    BOLD = "\033[1m"
    END = "\033[0m"

    @staticmethod
    def disable():
        """Color.disable() - Disable colors."""
        Color.BOLD = ""
        Color.END = ""

    @staticmethod
    def bold(buf):
        """Color.bold() - Make a string bold.

        Args:
            buf (str) - String to make bold.

        Returns:
            string wrapped in ANSI bold color codes.
        """
        return Color.BOLD + str(buf) + Color.END

    @staticmethod
    def highlight(substr, buf):
        """Color.highlight() - Highlight substrings within a string.

        Args:
            substr (str) - Substring to highlight.
            buf (str) - String containing potential substrings.

        Returns:
            string with substrings wrapped in ANSI bold color codes.
        """
        result = [Color.bold(x) if substr in x else x for x in buf.split()]
        return " ".join(result)


class Packet():
    """Packet class - Parses an Ethernet frame so you dont have to!@#"""
    # pylint: disable=too-many-instance-attributes
    def __init__(self, raw_packet):
        self.packet = raw_packet # Raw packet contents
        self.data = None         # Packet data
        self.ethertype = None    # Ethertype.
        self.protocol = None     # Protocol: TCP, UDP, ICMP, ARP, IGMP, ...
        self.saddr = None        # Source IP
        self.daddr = None        # Destination IP
        self.shwaddr = None      # Source MAC
        self.dhwaddr = None      # Destination MAC
        self.sport = None        # Source port
        self.dport = None        # Destination port
        self.ttl = None          # Time to Live
        self.seq = None          # Sequence number
        self.ack = None          # Acknowledgement Number
        self.window = None       # TCP window
        self.tcpflags = None     # TCP flags
        self.len = None          # Length
        self.checksum = None     # Checksum
        self.icmptype = None     # ICMP type
        self.icmpcode = None     # ICMP code

        # Constants
        self.ethernet_header_length = 14
        self.ip_header_length = 20
        self.ipv6_header_length = 16
        self.tcp_header_length = 20
        self.udp_header_length = 8
        self.icmp_header_length = 4

        # Parse Ethernet header
        self.ethernet_header = \
            unpack("!6s6sH", raw_packet[:self.ethernet_header_length])

        self.dhwaddr = self.mac_address(self.ethernet_header[0])
        self.shwaddr = self.mac_address(self.ethernet_header[1])
        self.ethertype = self.ethernet_header[2]

        # Check Ethertype and parse accordingly
        if self.ethertype == 0x0800: # IP
            self.parse_ip_header()

            if self.protocol == 6:
                self.parse_tcp_header()
            elif self.protocol == 17:
                self.parse_udp_header()
            elif self.protocol == 1:
                self.parse_icmp_header()
            elif self.protocol == 2:
                self.parse_igmp_header()
            else: # UNKNOWN PROTOCOL
                print(self.protocol, self.packet)

        if self.ethertype == 0x86dd: # IPv6
            self.parse_ipv6_header()

        if self.ethertype == 0x0806: # ARP
            self.parse_arp()

    def parse_arp(self):
        """Packet.parse_arp() - Parse ARP packets.
        TODO: finish this
        """
        self.protocol = "ARP"

    def parse_ipv6_header(self):
        """Packet.parse_ipv6_header() - Parse IPv6 packets.
        TODO: finish this
        """
        self.protocol = "IPv6"
        #offset = self.ethernet_header_length
        #ipv6_header = unpack("!LHBBLL",
        #                     self.packet[offset:offset+self.ipv6_header_length])

    def parse_igmp_header(self):
        """Packet.parse_igmp_header() - Parse IGMP header.
        TODO: finish this
        """
        self.protocol = "IGMP"

    def parse_icmp_header(self):
        """Packet.parse_icmp_header() - Parse ICMP header."""
        self.protocol = "ICMP"
        offset = self.ethernet_header_length + self.ip_header_length
        icmp_header = unpack("!BBH",
                             self.packet[offset:offset+self.icmp_header_length])
        self.icmptype = icmp_header[0]
        self.icmpcode = icmp_header[1]
        self.checksum = icmp_header[2]
        self.data = self.packet[offset + self.icmp_header_length:]

    def parse_udp_header(self):
        """Packet.parse_udp_header() - Parse UDP header."""
        self.protocol = "UDP"
        offset = self.ethernet_header_length + self.ip_header_length
        udp_header = unpack("!HHHH",
                            self.packet[offset:offset + self.udp_header_length])
        self.sport = udp_header[0]
        self.dport = udp_header[1]
        self.len = udp_header[2]
        self.checksum = udp_header[3]
        self.data = self.packet[offset + self.udp_header_length:]

    def parse_tcp_header(self):
        """Packet.parse_tcp_header() - Parse TCP header."""
        self.protocol = "TCP"
        offset = self.ethernet_header_length + self.ip_header_length
        tcp_header = unpack("!HHLLBBHHH",
                            self.packet[offset:offset + self.tcp_header_length])
        self.sport = tcp_header[0]
        self.dport = tcp_header[1]
        self.seq = tcp_header[2]
        self.ack = tcp_header[3]
        self.tcpflags = self.parse_tcp_flags(tcp_header[5])
        self.window = tcp_header[6]
        self.checksum = tcp_header[7]
        self.data = self.packet[offset+self.tcp_header_length:]

    @staticmethod
    def parse_tcp_flags(control):
        """parse_tcp_flags() - Determine which TCP flags are set.

        Args:
            control (str) - TCP control bytes

        Returns:
            tcpdump style flags.
        """
        tcp_flags = ""
        if control & 0x01: # FIN
            tcp_flags += "F"
        if control & 0x02: # SYN
            tcp_flags += "S"
        if control & 0x04: # RST
            tcp_flags += "R"
        if control & 0x08: # PSH
            tcp_flags += "P"
        if control & 0x10: # ACK
            tcp_flags += "A"
        if control & 0x20: # URG
            tcp_flags += "U"
        if control & 0x40: # ECE
            tcp_flags += "E"
        if control & 0x80: # CWR
            tcp_flags += "C"
        return tcp_flags

    def parse_ip_header(self):
        """Packet.parse_ip_header() - Parse IP header.
        TODO: make this complete. May need some of the other header elements
              for other tools instead of ttl, protocol, source, and destination
              http://www.networksorcery.com/enp/protocol/ip.htm
        """
        offset = self.ethernet_header_length + self.ip_header_length
        ip_header = unpack("!BBHHHBBH4s4s",
                           self.packet[self.ethernet_header_length:offset])

        self.ttl = ip_header[5]
        self.protocol = ip_header[6]
        self.saddr = socket.inet_ntoa(ip_header[8])
        self.daddr = socket.inet_ntoa(ip_header[9])

    @staticmethod
    def mac_address(address):
        """mac_address() - Convert 6 bytes to human-readable MAC address.

        Args:
            address - MAC address bytes.

        Returns:
            Human readable MAC address (00:11:22:33:44:55)
        """
        result = ""
        if len(address) != 6:
            return None
        for byte in address:
            result += "%.2x:" % byte
        return result[:-1] # Strip trailing colon


class Sniffer():
    """Sniffer class. Wrapper for pcapy."""
    def __init__(self, interface, promisc=1, bpf="", snaplen=65535, timeout=0):
        self.interface = interface
        self.promisc = promisc
        self.bpf = bpf
        self.snaplen = snaplen
        self.timeout = timeout
        self.sniffer = None

    def start(self):
        """Sniffer.start() - Start sniffing."""
        self.sniffer = pcapy.open_live(self.interface,
                                       self.snaplen,
                                       self.promisc,
                                       self.timeout)
        self.sniffer.setfilter(self.bpf)

    def next(self):
        """Sniffer.next() - Read next packet.

        Args:
            None.

        Returns:
            Packet object containing the current packet.
        """
        _, packet = self.sniffer.next()
        return Packet(packet)


def get_interface_ip(interface):
    """get_interface_ip() - Get an interface's IP address.

    Args:
        interface (str) - Name of interface. Example: eth0

    Returns:
        IP address in quad dot notation.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip = ioctl(sock.fileno(),
               0x8915,
               pack("256s", bytes(interface[:15], "utf-8")))[20:24]
    return socket.inet_ntoa(ip)


def netstat_search_process(ip, port, protocol="tcp"):
    """netstat_search_process() - Figure out which process is handling a
                                  IP:PORT pair.

    Args:
        ip (str) - IP address to search for.
        port (int) - Port to search for.
        protocol (str) - Protocol to search for. Default is "tcp."

    Returns:
        String containing the path to the responsible executable on success.
        None if it was unable to figure it out.

    TODO Test IPv6
    """
    if protocol not in ["tcp", "udp"]:
        raise ValueError("Invalid protocol: %s" % protocol)

    # Read /proc netstat entries into netstat_entries[]
    netstat_entries = []
    for netstat_file in ["/proc/net/%s" % protocol, "/proc/net/%s6" % protocol]:
        with open(netstat_file, "r") as netstat:
			# Skip header line
            next(netstat)
            entries = [x.split() for x in netstat.readlines()]
            netstat_entries += entries

    # Convert supplied ip and port to netstat's format for easy searching.
    search_string = \
        hex(unpack("<I", pack(">I", ip_address(ip).__int__()))[0])[2:].upper() + \
        ":" + \
        hex(int(port))[2:].zfill(4).upper()

    # Search netstat entries for ip:port.
    for entry in netstat_entries:
        inode = entry[9]
        if int(inode) == 0:
            continue

        if search_string not in entry:
            continue

        # If we made it here, we have a match.
        # Search /proc/PID/fd/* for the inode referenced by netstat.
        for proc in glob("/proc/[0-9]*/fd/[0-9]*"):
            try:
                link = readlink(proc)
            except FileNotFoundError:
                continue
            if inode == link[link.find("[") + 1:link.rfind("]")]:
                # Example of link: "socket:[1928838]"; slice between [ and ].
                pid = proc.split("/")[2]
                exe = readlink("/proc/" + pid + "/exe")
                return exe

    # Nothing found.
    return None


def main():
    """main function."""
    capture = Sniffer("eth0", bpf="not port 22")
    capture.start()

    local_ip = get_interface_ip("eth0")

    timefilter = TimingBloomFilter(50000, 0.01, 60*60)

    while True:
        packet = capture.next()
        element = None

        if packet.protocol in ["TCP", "UDP"]:
            exe = netstat_search_process(packet.saddr,
                                         packet.sport,
                                         protocol=packet.protocol.lower())
            if exe is None:
                exe = netstat_search_process(packet.daddr,
                                             packet.dport,
                                             protocol=packet.protocol.lower())

        if packet.protocol == "TCP" and "S" in packet.tcpflags:
            element = "TCP: [%s] %s -> %s:%s %s" % \
                (packet.tcpflags,
                 packet.saddr,
                 packet.daddr,
                 str(packet.dport),
                 exe if exe else "")
        elif packet.protocol == "UDP":
            element = "UDP: %s -> %s:%s %s" % \
                (packet.saddr,
                 packet.daddr,
                 str(packet.dport),
                 exe if exe else "")
        elif packet.protocol == "ICMP" and packet.icmptype in [0, 8]:
            element = "ICMP: %s -> %s: %s" % \
                (packet.saddr, packet.daddr, packet.data[20:])

        # Output packet if it isn't in the filter, highlighting our
        # IP address to visualize the data easier.
        if element and timefilter.lookup(element) is False:
            timefilter.add(element)
            print("[%s] %s" % \
                (ctime(time()), Color.highlight(local_ip, element)))


if __name__ == "__main__":
    main()

