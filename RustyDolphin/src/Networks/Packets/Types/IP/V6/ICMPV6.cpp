#include "ICMPV6.h"

#include "../../../../../Base/Logger.h"
#include "../../../../../Networks/Capture.h"
#include <iostream>
#include <sstream>




ICMPV6::ICMPV6(pcap_pkthdr* header, const u_char* pkt_data) : IPV6(header, pkt_data) {
	m_type = pkt_data[pos++];
	m_code = pkt_data[pos++];
	m_ICMPChecksum = (long)parseLong(&pos, pos + 2);
	m_restOfHeader = (long)parseLong(&pos, pos + 4);
}

std::string ICMPV6::toString() {
	std::stringstream ss;

	ss << "ICMPV6 packet at " << m_time << " of type " << m_type << " of code " << m_code << " (with checksum " << m_ICMPChecksum << " and rest of header is " << m_restOfHeader << ")\n";

	return ss.str();
}

json ICMPV6::jsonify() {
	auto j = IPV6::jsonify();

	j["ICMPV6"] = "start";
	j["Type"] = m_type;
	j["Code"] = m_code;
	j["ICMP Checksum"] = m_ICMPChecksum;
	j["The Rest of the Header"] = m_restOfHeader;

	return j;
}