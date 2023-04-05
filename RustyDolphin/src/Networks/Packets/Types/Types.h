#pragma once


#include "Eth/Eth.h"
#include "IP/IP.h"

#include <memory>


#define PKT             std::unique_ptr<Packet>
#define ARP_PKT         std::unique_ptr<ARP>
#define IPV4_PKT        std::unique_ptr<IPV4>
#define TCPV4_PKT       std::unique_ptr<TCPV4>
#define UDPV4_PKT       std::unique_ptr<UDPV4>
#define IGMPV4_PKT      std::unique_ptr<IGMPV4>
#define IPV6_PKT        std::unique_ptr<IPV6>
#define TCPV6_PKT       std::unique_ptr<TCPV6>
#define UDPV6_PKT       std::unique_ptr<UDPV6>
#define IGMPV6_PKT      std::unique_ptr<IGMPV6>