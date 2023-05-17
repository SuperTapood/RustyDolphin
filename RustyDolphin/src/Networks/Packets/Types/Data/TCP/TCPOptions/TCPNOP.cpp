#include "TCPNOP.h"

TCPNOP::TCPNOP() : TCPOption(1) {
	m_size = 1;
}

const std::string TCPNOP::toString() {
	return "No Operation (NOP)";
}