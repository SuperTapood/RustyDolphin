#include "TCPWScale.h"

TCPWScale::TCPWScale(Packet* packet) : TCPOption(3) {
	m_len = packet->parseChar();
	m_shift = packet->parseChar();
	m_size = m_len;
}

const std::string TCPWScale::toString() {
	return std::format("Window Sacle: {} (multiply by {})", m_shift, 2 << (m_shift - 1));
}