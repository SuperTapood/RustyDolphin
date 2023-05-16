#include "HopByHop.h"
#include <iostream>

HopByHop::HopByHop(Packet* packet) : IPV6Option(packet) {
	auto end = packet->getPos() + (m_length + 6);

	for (; packet->getPos() < end;) {
		m_options.emplace_back(packet);
	}
}