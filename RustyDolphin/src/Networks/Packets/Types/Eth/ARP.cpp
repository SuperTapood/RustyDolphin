#include "ARP.h"

#include <sstream>

ARP::ARP(pcap_pkthdr* header, const u_char* pkt_data, unsigned int idx) : Packet(header, pkt_data, idx) {
	m_hardType = parseShort();

	m_protoType = parseShort();

	m_hardSize = pkt_data[pos++];

	m_protoSize = pkt_data[pos++];

	m_opcode = parseShort();

	m_sendMAC = parseMAC(m_hardSize);

	m_sendAddr = parseIPV4(m_protoSize);

	m_targetMAC = parseMAC(m_hardSize);

	m_targetAddr = parseIPV4(m_protoSize);

	Packet::m_strType = "ARP";
}

std::string ARP::toString() {
	std::stringstream ss;

	ss << "ARP Packet at " << m_time;

	if (m_opcode == 1) {
		ss << " who tf is " << m_targetAddr << "? Tell " << m_sendAddr;
	}
	else if (m_opcode == 2) {
		ss << " " << m_sendAddr << " is at physical address " << m_sendMAC;
	}
	else {
		ss << " unknown opcode " << m_opcode;
	}

	ss << "\n";

	return ss.str();
}

json ARP::jsonify() {
	auto j = Packet::jsonify();

	j["ARP"] = "start";
	j["hardware type"] = m_hardType;
	j["protocol type"] = m_protoType;
	j["hardware size"] = m_hardSize;
	j["protocol size"] = m_protoSize;
	j["operation code"] = m_opcode;
	j["sender MAC Address"] = m_sendMAC;
	j["sender IP Address"] = m_sendAddr;
	j["target MAC Address"] = m_targetMAC;
	j["target IP Address"] = m_targetAddr;

	return j;
}