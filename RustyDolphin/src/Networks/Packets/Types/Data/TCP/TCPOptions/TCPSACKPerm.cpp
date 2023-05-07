#include "TCPSACKPerm.h"


TCPSACKPerm::TCPSACKPerm(pcap_pkthdr* header, const u_char* pkt_data, unsigned int* pos) : TCPOption(3) {
	m_len = pkt_data[(*pos)++];
}

std::string TCPSACKPerm::toString() {
	std::stringstream ss;

	ss << "TCP Option SACK Permitted of length " << m_len;

	return ss.str();
}