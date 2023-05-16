#include "TCPSACK.h"

TCPSACK::TCPSACK(Packet* packet) : TCPOption(5) {
	m_len = packet->parseChar();

	m_edges = (m_len - 2) / 8;

	m_Ledges = new unsigned int[m_edges];
	m_Redges = new unsigned int[m_edges];

	for (int i = 0; i < m_edges; i++) {
		m_Ledges[i] = (unsigned int)packet->parseInt();
		m_Redges[i] = (unsigned int)packet->parseInt();
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