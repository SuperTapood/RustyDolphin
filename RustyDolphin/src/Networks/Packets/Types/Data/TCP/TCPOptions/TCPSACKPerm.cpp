#include "TCPSACKPerm.h"

TCPSACKPerm::TCPSACKPerm(Packet* packet) : TCPOption(3) {
	m_len = packet->parseChar();
}

std::string TCPSACKPerm::toString() {
	std::stringstream ss;

	ss << "TCP Option SACK Permitted of length " << m_len;

	return ss.str();
}