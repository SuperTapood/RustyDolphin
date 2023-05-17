#include "TCPSACKPerm.h"

TCPSACKPerm::TCPSACKPerm(Packet* packet) : TCPOption(3) {
	m_len = packet->parseChar();
	m_size = m_len;
}

const std::string TCPSACKPerm::toString() {
	return "SACK Permitted";
}