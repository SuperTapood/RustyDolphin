#pragma once

// easier to type
// easier to include

#include "Eth/Packet.h"
#include "Eth/ARP.h"
#include "IP/IP.h"
#include "Data/ICMP/ICMP.h"
#include "Data/ICMP/ICMPV6.h"
#include "Data/IGMP/IGMP.h"
#include "Data/TCP/TCP.h"
#include "Data/UDP/UDP.h"

#define PKT             Packet*
#define ARP_PKT         ARP*
#define IPV4_PKT        IPV4*
#define TCPV4_PKT       TCP<IPV4>*
#define UDPV4_PKT       UDP<IPV4>*
#define IGMPV4_PKT      IGMP<IPV4>*
#define ICMPV4_PKT      ICMP*
#define IPV6_PKT        IPV6*
#define TCPV6_PKT       TCP<IPV6>*
#define UDPV6_PKT       UDP<IPV6>*
#define IGMPV6_PKT      IGMP<IPV6>*
#define ICMPV6_PKT      ICMPV6*