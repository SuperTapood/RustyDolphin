#include "TCPSACK.h"

TCPSACK::TCPSACK(pcap_pkthdr* header, const u_char* pkt_data, unsigned int* pos) : TCPOption(5) {
	m_len = pkt_data[(*pos)++];

	m_edges = (m_len - 2) / 8;

	m_Ledges = new unsigned int[m_edges];
	m_Redges = new unsigned int[m_edges];

	for (int i = 0; i < m_edges; i++) {
		m_Ledges[i] = (unsigned int)parseLong(pos, (*pos) + 4, pkt_data);
		m_Redges[i] = (unsigned int)parseLong(pos, (*pos) + 4, pkt_data);
	}
}

std::string TCPSACK::toString() {
	std::stringstream ss;

	ss << "TCP Option SACK of " << m_edges << " edges (";

	for (int i = 0; i < m_edges; i++) {
		ss << " from " << m_Ledges[i] << " to " << m_Redges[i] << ",";
	}

	ss << ")";

	return ss.str();
}