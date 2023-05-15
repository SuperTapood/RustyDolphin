#include "Packets.h"
#include <iostream>

#include <ws2def.h>
#include "../../Base/Logger.h"

constexpr auto ETHERTYPE_IPV4 = 0x0800;
constexpr auto ETHERTYPE_ARP = 0x0806;
constexpr auto ETHERTYPE_IPV6 = 0x86DD;

constexpr auto IPV4_PROTO_POS = 23;
constexpr auto IPV6_PROTO_POS = 20;

IPV4_PKT fromIPV4(pcap_pkthdr* header, const u_char* pkt_data, unsigned int idx) {
	int proto = pkt_data[IPV4_PROTO_POS];

	switch (proto) {
	case IPPROTO_TCP:
		return new TCP<IPV4>(header, pkt_data, idx);
	case IPPROTO_UDP:
		return new UDP<IPV4>(header, pkt_data, idx);
	case IPPROTO_IGMP:
		return new IGMP<IPV4>(header, pkt_data, idx);
	case IPPROTO_ICMP:
		return new ICMP(header, pkt_data, idx);
	default:
#ifdef _DEBUG
		std::stringstream ss;
		ss << "unknown v4 protocol: " << proto;
		Logger::log(ss.str());
#endif
		break;
	}

	Logger::log("unknown v4 protocol: ");
	std::cout << "bad proto " << proto << std::endl;

	return new IPV4(header, pkt_data, idx);
}

IPV6_PKT fromIPV6(pcap_pkthdr* header, const u_char* pkt_data, unsigned int idx, int proto_pos = IPV6_PROTO_POS) {
	int proto = pkt_data[proto_pos];

	switch (proto) {
	case IPPROTO_HOPOPTS:
		return fromIPV6(header, pkt_data, idx, 54);
	case IPPROTO_TCP:
		return new TCP<IPV6>(header, pkt_data, idx);
	case IPPROTO_UDP:
		return new UDP<IPV6>(header, pkt_data, idx);
	case IPPROTO_ICMPV6:
		return new ICMPV6(header, pkt_data, idx);
	default:
#ifdef _DEBUG
		std::stringstream ss;
		ss << "unknown v6 protocol: " << proto;
		Logger::log(ss.str());
#endif
		break;
	}

	return new IPV6(header, pkt_data, idx);
}

PKT fromRaw(pcap_pkthdr* header, const u_char* pkt_data, unsigned int idx) {
	u_char t1 = pkt_data[12];
	u_char t2 = pkt_data[13];
	int type = (t1 << 8) | t2;

	switch (type) {
	case ETHERTYPE_IPV4:
		return fromIPV4(header, pkt_data, idx);
	case ETHERTYPE_IPV6:
		return fromIPV6(header, pkt_data, idx);
	case ETHERTYPE_ARP:
		return new ARP(header, pkt_data, idx);
	default:
#ifdef _DEBUG
		std::stringstream ss;
		ss << "unknown packet type: " << type << " at position " << idx;
		Logger::log(ss.str());
#endif
		break;
	}

	return new Packet(header, pkt_data, idx);
}