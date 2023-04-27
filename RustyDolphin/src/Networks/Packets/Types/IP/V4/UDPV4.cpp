#include "UDPV4.h"

#include "../../../../../Win/SDK.h"

#include <sstream>

UDPV4::UDPV4(pcap_pkthdr* header, const u_char* pkt_data) : IPV4(header, pkt_data) {
	m_srcPort = (int)parseLong(&pos, pos + 2);

	m_destPort = (int)parseLong(&pos, pos + 2);

	m_length = (int)parseLong(&pos, pos + 2);

	m_UDPChecksum = (int)parseLong(&pos, pos + 2);
}

std::string UDPV4::toString() {
	std::stringstream ss;

	ss << "UDPV4 Packet at " << m_time << " from " << m_srcAddr << " at port " << m_srcPort << " to " << m_destAddr << " at port " << m_destPort;

	ss << ". Proccess = ";

	auto proc = SDK::getProcFromPort(m_srcPort);

	if (proc == "<UNKNOWN>") {
		proc = SDK::getProcFromPort(m_destPort);
	}

	ss << proc << "\n";

	return ss.str();
}

json UDPV4::jsonify() {
	auto j = IPV4::jsonify();

	j["UDPV4"] = "start";
	j["Source Port"] = m_srcPort;
	j["Destination Port"] = m_destPort;
	j["UDP Length"] = m_length;
	j["UDP Checksum"] = m_UDPChecksum;

	return j;
}