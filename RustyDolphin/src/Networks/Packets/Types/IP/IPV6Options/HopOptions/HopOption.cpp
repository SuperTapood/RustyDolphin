#include "HopOption.h"

HopOption::HopOption(const u_char* pkt_data, unsigned int* pos) {
	m_type = pkt_data[(*pos)++];
	m_length = pkt_data[(*pos)++];

	auto size = m_length;

	if (size > 0) {
		m_data.reserve(size * 2); // Each byte will be represented by 2 hexadecimal characters

		for (int end = (*pos) + size; (*pos) < end; (*pos)++) {
			char buf[3];
			sprintf_s(buf, "%02x", (int)pkt_data[(*pos)]);
			m_data.append(buf);
		}
	}
}