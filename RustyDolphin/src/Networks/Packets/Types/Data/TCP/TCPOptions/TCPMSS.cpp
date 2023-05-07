#include "TCPMSS.h"

TCPMSS::TCPMSS(pcap_pkthdr* header, const u_char* pkt_data, unsigned int* pos) : TCPOption(2) {
	m_len = pkt_data[(*pos)++];
	m_value = (short)parseLong(pos, (*pos) + 2, pkt_data);
}

std::string TCPMSS::toString() {
	std::stringstream ss;

	ss << "TCP Option MSS of value" << m_value;

	return ss.str();
}