#include "IPV6Option.h"

IPV6Option::IPV6Option(Packet* packet) {
	m_nextHeader = packet->parseChar();
	m_length = packet->parseChar();
}