#include "UDPV6.h"

#include "../../../../../Win/SDK.h"

#include <sstream>

UDPV6::UDPV6(pcap_pkthdr* header, const u_char* pkt_data) : IPV6(header, pkt_data) {
	srcPort = (int)parseLong(&pos, pos + 2);

	destPort = (int)parseLong(&pos, pos + 2);

	length = (int)parseLong(&pos, pos + 2);

	checksum = (int)parseLong(&pos, pos + 2);
}

std::string UDPV6::toString() {
	std::stringstream ss;

	ss << "UDP Packet (V4) at " << time << " from " << srcAddr << " (port " << srcPort << " - " << SDK::getProcFromPort(srcPort) << " to " << destAddr << " (port " << destPort << " - " << SDK::getProcFromPort(destPort);

	return ss.str();
}