#include "RouterAlert.h"

#include <sstream>

RouterAlert::RouterAlert(pcap_pkthdr* header, const u_char* pkt_data, unsigned int* pos) : IPV4Option(20) {
	m_copyOnFrag = pkt_data[*pos] & 0x10000000;
	m_clsType = pkt_data[*pos] & 0x01100000;
	m_code = pkt_data[*pos] & 0x00011111;

	(*pos)++;

	m_length = pkt_data[(*pos)++];

	m_extra = (long)parseLong(pos, (*pos) + (m_length - 2), pkt_data);
}

std::string RouterAlert::toString() {
	std::stringstream ss;

	ss << "Route Alert Option of length " << m_length;

	return ss.str();
}