#pragma once

#include <pcap.h>

/* 4 bytes IP address */
using ip_address = struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
};

/* IPv4 header */
using ip_header = struct ip_header {
	u_char  ver_ihl; // Version (4 bits) + IP header length (4 bits)
	u_char  tos;     // Type of service
	u_short tlen;    // Total length
	u_short identification; // Identification
	u_short flags_fo; // Flags (3 bits) + Fragment offset (13 bits)
	u_char  ttl;      // Time to live
	u_char  proto;    // Protocol
	u_short crc;      // Header checksum
	ip_address  saddr; // Source address
	ip_address  daddr; // Destination address
	u_int  op_pad;     // Option + Padding
};

/* UDP header*/
using udp_header = struct udp_header {
	u_short sport; // Source port
	u_short dport; // Destination port
	u_short len;   // Datagram length
	u_short crc;   // Checksum
};