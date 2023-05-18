#include "RouterAlert.h"

#include <sstream>
#include <format>

RouterAlert::RouterAlert(Packet* packet) : IPV4Option(20, "Router Alert") {
	unsigned char d = packet->parseChar();

	m_copyOnFrag = d & 128;
	m_clsType = d & 96;
	m_code = d & 31;

	m_length = packet->parseChar();

	m_extra = packet->parseShort();

	if (m_extra == 0) {
		m_value = "Router Shall examine Packet (0)";
	}
	else if (m_extra > 0 && m_extra < 33) {
		m_value = std::format("Aggregated Reservation Nesting Level {} ({})", m_extra, m_extra);
	}
	else if (m_extra > 32 && m_extra < 65) {
		m_value = std::format("Aggregated Reservation Nesting Level {} ({})", m_extra - 33, m_extra);
	}
	else if (m_extra == 65) {
		m_value = "NSIS NATFW NSLP (65)";
	}
	else {
		m_value = std::format("Bad Router Alert Code {}", m_extra);
	}

	data.push_back(std::format("\t\t\tCopy on fragmentation: {}", m_copyOnFrag ? "Yes" : "No"));
	data.push_back(std::format("\t\t\tClass Type Code: {} ({})", m_clsType == 0 ? "Control" : "Debugging and measurement", m_clsType));
	data.push_back("\t\t\tNumber: Router Alert (20)");
}

std::string RouterAlert::toString() {
	std::stringstream ss;

	ss << "Route Alert Option of length " << m_length;

	return ss.str();
}