#include "UDPV6.h"

#include "../../../../../Win/SDK.h"

#include <sstream>

UDPV6::UDPV6(pcap_pkthdr* header, const u_char* pkt_data) : IPV6(header, pkt_data) {
	m_srcPort = (int)parseLong(&pos, pos + 2);

	m_destPort = (int)parseLong(&pos, pos + 2);

	m_length = (int)parseLong(&pos, pos + 2);

	m_UDPChecksum = (int)parseLong(&pos, pos + 2);
}

std::string UDPV6::toString() {
	std::stringstream ss;

	ss << "UDP Packet (V4) at " << time << " from " << m_srcAddr << " (port " << m_srcPort << " - " << SDK::getProcFromPort(m_srcPort) << " to " << m_destAddr << " (port " << m_destPort << " - " << SDK::getProcFromPort(m_destPort) << "\n";

	return ss.str();
}

json UDPV6::jsonify() {
	auto j = UDPV6::jsonify();

	j["UDPV6"] = "start";
	j["Source Port"] = m_srcPort;
	j["Destination Port"] = m_destPort;
	j["UDP Length"] = m_length;
	j["UDP Checksum"] = m_UDPChecksum;

	return j;
}