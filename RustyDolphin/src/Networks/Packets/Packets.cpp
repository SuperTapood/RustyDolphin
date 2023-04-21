#include "Packets.h"
#include <iostream>

#include <ws2def.h>
#include "../../Base/Logger.h"

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IPV6 0x86DD

namespace {
	IPV4_PKT fromIPV4(pcap_pkthdr* header, const u_char* pkt_data) {
		int proto = pkt_data[23];

		switch (proto) {
		case IPPROTO_TCP:
			return new TCPV4(header, pkt_data);
		case IPPROTO_UDP:
			return new UDPV4(header, pkt_data);
		case IPPROTO_IGMP:
			return new IGMPV4(header, pkt_data);
		}

		Logger::log("unknown v4 protocol: ");

		return new IPV4(header, pkt_data);
	}

	IPV6_PKT fromIPV6(pcap_pkthdr* header, const u_char* pkt_data) {
		int proto = pkt_data[20];

		switch (proto) {
		case IPPROTO_TCP:
			return new TCPV6(header, pkt_data);
		case IPPROTO_UDP:
			return new UDPV6(header, pkt_data);
		}

		Logger::log("unknown v6 protocol: ");
		std::cout << "bad proto " << proto << std::endl;

		return new IPV6(header, pkt_data);
	}
}

PKT fromRaw(pcap_pkthdr* header, const u_char* pkt_data) {
	u_char t1 = pkt_data[12];
	u_char t2 = pkt_data[13];
	int type = (t1 << 8) | t2;

	switch (type) {
	case ETHERTYPE_IPV4:
		return fromIPV4(header, pkt_data);
	case ETHERTYPE_IPV6:
		return fromIPV6(header, pkt_data);
	case ETHERTYPE_ARP:
		return new ARP(header, pkt_data);
	}

	Logger::log("unknown type: ");

	return new Packet(header, pkt_data);
}