#include "TCPWScale.h"


TCPWScale::TCPWScale(pcap_pkthdr* header, const u_char* pkt_data, unsigned int* pos) : TCPOption(3) {
	m_len = pkt_data[(*pos)++];
	m_shift = pkt_data[(*pos)++];
}

std::string TCPWScale::toString() {
	std::stringstream ss;

	ss << "TCP Option Window Scale of length " << m_len << " and shift " << m_shift << " (actual " << (2 << m_shift) << ")";

	return ss.str();
}