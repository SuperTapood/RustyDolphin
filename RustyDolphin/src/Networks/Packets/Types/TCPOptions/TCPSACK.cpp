#include "TCPSACK.h"

TCPSACK::TCPSACK(pcap_pkthdr* header, const u_char* pkt_data, int* pos) : TCPOption(5) {
	m_len = pkt_data[(*pos)++];

	m_edges = (m_len - 2) / 8;

	m_Ledges = new long long[m_edges];
	m_Redges = new long long[m_edges];

	for (int i = 0; i < m_edges; i++) {
		m_Ledges[i] = parseLong(pos, (*pos) + 4, pkt_data);
		m_Redges[i] = parseLong(pos, (*pos) + 4, pkt_data);
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