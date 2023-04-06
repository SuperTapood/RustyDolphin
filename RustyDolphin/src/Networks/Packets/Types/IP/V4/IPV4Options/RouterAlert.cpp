#include "RouterAlert.h"

#include <sstream>

RouterAlert::RouterAlert(pcap_pkthdr* header, const u_char* pkt_data, int* pos) : IPV4Option(20) {
	copyOnFrag = pkt_data[*pos] & 0x10000000;
	clsType = pkt_data[*pos] & 0x01100000;
	code = pkt_data[*pos] & 0x00011111;

	(*pos)++;

	length = pkt_data[(*pos)++];

	extra = (long)parseLong(pos, (*pos) + (length - 2), pkt_data);
}

std::string RouterAlert::toString() {
	std::stringstream ss;

	ss << "Route Alert Option of length " << length;

	return ss.str();
}