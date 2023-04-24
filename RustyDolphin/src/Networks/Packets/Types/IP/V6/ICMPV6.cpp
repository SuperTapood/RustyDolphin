#include "ICMPV6.h"

#include "../../../../../Base/Logger.h"
#include "../../../../../Networks/Capture.h"
#include <iostream>
#include <sstream>




ICMPV6::ICMPV6(pcap_pkthdr* header, const u_char* pkt_data) : IPV6(header, pkt_data) {
	type = pkt_data[pos++];
	code = pkt_data[pos++];
	ICMPChecksum = (long)parseLong(&pos, pos + 2);
	restOfHeader = (long)parseLong(&pos, pos + 4);
}

std::string ICMPV6::toString() {
	std::stringstream ss;

	ss << "ICMPV6 packet at " << m_time << " of type " << type << " of code " << code << " (with checksum " << ICMPChecksum << " and rest of header is " << restOfHeader << ")\n";

	return ss.str();
}

json ICMPV6::jsonify() {
	auto j = IPV6::jsonify();

	j["ICMPV6"] = "start";
	j["Type"] = type;
	j["Code"] = code;
	j["ICMP Checksum"] = ICMPChecksum;
	j["The Rest of the Header"] = restOfHeader;

	return j;
}