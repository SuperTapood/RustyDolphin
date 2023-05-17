#include "TCPMSS.h"

TCPMSS::TCPMSS(Packet* packet) : TCPOption(2) {
	m_len = packet->parseChar();
	m_value = packet->parseShort();
	m_size = m_len;
}

const std::string TCPMSS::toString() {
	return std::format("Maximum Segment Size: {} bytes", m_value);
}