#include "IGMPV4.h"

#include <sstream>

IGMPV4::IGMPV4(pcap_pkthdr* header, const u_char* pkt_data) : IPV4(header, pkt_data){
	groupType = pkt_data[pos++];
	maxResp = pkt_data[pos++] / 10;
	checksum = (int)parseLong(&pos, pos + 2);
	multicastAddr = parseIPV4(&pos, pos + 4);
}

std::string IGMPV4::toString() {
	std::stringstream ss;

	ss << "IGMP of group type " << groupType << " max resp time is " << maxResp << " for multicast addr: " << multicastAddr;

	return ss.str();
}