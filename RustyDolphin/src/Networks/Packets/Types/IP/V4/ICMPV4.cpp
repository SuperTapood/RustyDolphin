#include "ICMPV4.h"

#include "../../../../../Base/Logger.h"
#include "../../../../../Networks/Capture.h"
#include <iostream>




ICMPV4::ICMPV4(pcap_pkthdr* header, const u_char* pkt_data) : IPV4(header, pkt_data) {
	m_ICMPtype = pkt_data[pos++];
	m_code = pkt_data[pos++];
	m_ICMPChecksum = (long)parseLong(&pos, pos + 2);
	m_restOfHeader = (long)parseLong(&pos, pos + 4);
}

std::string ICMPV4::toString() {
	std::stringstream ss;

	ss << "ICMPV4 packet at " << m_time << " of type " << m_ICMPtype << " of code " << m_code << " (with checksum " << m_ICMPChecksum << " and rest of header is " << m_restOfHeader << ")\n";

	return ss.str();
}

json ICMPV4::jsonify() {
	auto j = IPV4::jsonify();

	j["ICMPV4"] = "start";
	j["Type"] = m_ICMPtype;
	j["Code"] = m_code;
	j["ICMP Checksum"] = m_ICMPChecksum;
	j["The Rest of the Header"] = m_restOfHeader;

	return j;
}