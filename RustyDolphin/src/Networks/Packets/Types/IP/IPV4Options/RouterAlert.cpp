#include "RouterAlert.h"

#include <sstream>
#include <format>

RouterAlert::RouterAlert(pcap_pkthdr* header, const u_char* pkt_data, unsigned int* pos) : IPV4Option(20, "Router Alert") {
	m_copyOnFrag = pkt_data[*pos] & 0x10000000;
	m_clsType = pkt_data[*pos] & 0x01100000;
	m_code = pkt_data[*pos] & 0x00011111;

	(*pos)++;

	m_length = pkt_data[(*pos)++];

	m_extra = (long)parseLong(pos, (*pos) + (m_length - 2), pkt_data);

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