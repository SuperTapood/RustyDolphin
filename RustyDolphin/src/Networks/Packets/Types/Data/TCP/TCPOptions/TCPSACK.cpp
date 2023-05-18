#include "TCPSACK.h"

TCPSACK::TCPSACK(Packet* packet) : TCPOption(5) {
	auto start = packet->getPos() - 1;
	m_len = packet->parseChar();

	m_edges = (m_len - 2) / 8;

	m_LEdges = new unsigned int[m_edges];
	m_REdges = new unsigned int[m_edges];

	for (int i = 0; i < m_edges; i++) {
		m_LEdges[i] = (unsigned int)packet->parseInt();
		m_REdges[i] = (unsigned int)packet->parseInt();
	}

	m_size = packet->getPos() - start;
}

const std::string TCPSACK::toString() {
	std::stringstream ss;

	ss << "SACK ";

	for (int i = 0; i < m_edges; i++) {
		ss << m_LEdges[i] << "-" << m_REdges[i] << " ";
	}

	return ss.str();
}