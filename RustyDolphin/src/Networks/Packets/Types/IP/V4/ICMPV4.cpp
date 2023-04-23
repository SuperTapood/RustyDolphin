#include "ICMPV4.h"

#include "../../../../../Base/Logger.h"
#include "../../../../../Networks/Capture.h"
#include <iostream>




ICMPV4::ICMPV4(pcap_pkthdr* header, const u_char* pkt_data) : IPV4(header, pkt_data) {
	type = pkt_data[pos++];
	code = pkt_data[pos++];
	ICMPChecksum = (long)parseLong(&pos, pos + 2);
	restOfHeader = (long)parseLong(&pos, pos + 4);
}

std::string ICMPV4::toString() {
	std::stringstream ss;

	ss << "ICMPV4 packet at " << m_time << " of type " << type << " of code " << code << " (with checksum " << ICMPChecksum << " and rest of header is " << restOfHeader << ")\n";

	return ss.str();
}

json ICMPV4::jsonify() {
	auto j = IPV4::jsonify();

	j["ICMPV4"] = "start";
	j["Type"] = type;
	j["Code"] = code;
	j["ICMP Checksum"] = ICMPChecksum;
	j["The Rest of the Header"] = restOfHeader;

	return j;
}