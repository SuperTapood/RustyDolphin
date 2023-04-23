#include "UDPV4.h"

#include "../../../../../Win/SDK.h"

#include <sstream>

UDPV4::UDPV4(pcap_pkthdr* header, const u_char* pkt_data) : IPV4(header, pkt_data) {
	srcPort = (int)parseLong(&pos, pos + 2);

	destPort = (int)parseLong(&pos, pos + 2);

	length = (int)parseLong(&pos, pos + 2);

	checksum = (int)parseLong(&pos, pos + 2);
}

std::string UDPV4::toString() {
	std::stringstream ss;

	ss << "UDP Packet (V4) at " << m_time << " from " << srcAddr << " (port " << srcPort << " - " << SDK::getProcFromPort(srcPort) << " to " << destAddr << " (port " << destPort << " - " << SDK::getProcFromPort(destPort) << "))\n";

	return ss.str();
}

json UDPV4::jsonify() {
	auto j = IPV4::jsonify();

	j["UDPV4"] = "start";
	j["Source Port"] = srcPort;
	j["Destination Port"] = destPort;
	j["UDP Length"] = length;
	j["UDP Checksum"] = checksum;

	return j;
}