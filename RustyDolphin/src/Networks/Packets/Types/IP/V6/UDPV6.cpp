#include "UDPV6.h"

#include "../../../../../Win/SDK.h"

#include <sstream>

UDPV6::UDPV6(pcap_pkthdr* header, const u_char* pkt_data) : IPV4(header, pkt_data) {
	auto a = pkt_data[34];
	auto b = pkt_data[35];
	srcPort = (a << 8) | b;

	a = pkt_data[36];
	b = pkt_data[37];
	destPort = (a << 8) | b;

	a = pkt_data[38];
	b = pkt_data[39];
	length = (a << 8) | b;

	a = pkt_data[40];
	b = pkt_data[41];
	checksum = (a << 8) | b;
}

std::string UDPV6::toString() {
	std::stringstream ss;

	ss << "UDP Packet (V4) at " << time << " from " << srcAddr << " (port " << srcPort << " - " << SDK::getProcFromPort(srcPort) << " to " << destAddr << " (port " << destPort << " - " << SDK::getProcFromPort(destPort);

	return ss.str();
}