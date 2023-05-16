#include "TCPWScale.h"

TCPWScale::TCPWScale(Packet* packet) : TCPOption(3) {
	m_len = packet->parseChar();
	m_shift = packet->parseChar();
}

std::string TCPWScale::toString() {
	std::stringstream ss;

	ss << "TCP Option Window Scale of length " << m_len << " and shift " << m_shift << " (actual " << (2 << m_shift) << ")";

	return ss.str();
}