#include "HopByHop.h"
#include <iostream>

HopByHop::HopByHop(const u_char* pkt_data, unsigned int* pos) : IPV6Option(pkt_data, pos) {
	auto end = *pos + (m_length + 6);

	for (; *pos < end;) {
		m_options.emplace_back(pkt_data, pos);
	}

}