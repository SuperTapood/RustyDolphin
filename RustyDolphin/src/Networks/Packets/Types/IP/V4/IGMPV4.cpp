#include "IGMPV4.h"

#include <sstream>

IGMPV4::IGMPV4(pcap_pkthdr* header, const u_char* pkt_data) : IPV4(header, pkt_data) {
	m_groupType = pkt_data[pos++];
	m_maxResp = pkt_data[pos++] / 10;
	m_checksum = (int)parseLong(&pos, pos + 2);
	m_multicastAddr = parseIPV4(&pos, pos + 4);
}

std::string IGMPV4::toString() {
	std::stringstream ss;

	ss << "IGMP of group type " << m_groupType << " max resp time is " << m_maxResp << " for multicast addr: " << m_multicastAddr << "\n";

	return ss.str();
}

json IGMPV4::jsonify() {
	auto j = IPV4::jsonify();

	j["IGMP"] = "start";
	j["Group Type"] = m_groupType;
	j["Max Response Time"] = m_maxResp;
	j["IGMP Checksum"] = m_checksum;
	j["Multicast Address"] = m_multicastAddr;

	return j;
}