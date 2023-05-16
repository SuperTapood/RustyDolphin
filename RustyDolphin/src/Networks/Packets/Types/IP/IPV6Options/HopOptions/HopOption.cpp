#include "HopOption.h"

HopOption::HopOption(Packet* packet) {
	m_type = packet->parseChar();
	m_length = packet->parseChar();

	auto size = m_length;

	if (size > 0) {
		m_data.reserve(size * 2); // Each byte will be represented by 2 hexadecimal characters

		for (int end = packet->getPos() + size; packet->getPos() < end;) {
			char buf[3];
			sprintf_s(buf, "%02x", (int)packet->parseChar());
			m_data.append(buf);
		}
	}
}