#include "TCPMSS.h"

TCPMSS::TCPMSS(Packet* packet) : TCPOption(2) {
	m_len = packet->parseChar();
	m_value = packet->parseShort();
}

std::string TCPMSS::toString() {
	std::stringstream ss;

	ss << "TCP Option MSS of value" << m_value;

	return ss.str();
}