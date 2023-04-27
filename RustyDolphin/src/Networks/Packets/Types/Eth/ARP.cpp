#include "ARP.h"

#include <sstream>

ARP::ARP(pcap_pkthdr* header, const u_char* pkt_data) : Packet(header, pkt_data) {
	auto a = pkt_data[pos++];
	auto b = pkt_data[pos++];
	m_hardType = (a << 8) | b;

	a = pkt_data[pos++];
	b = pkt_data[pos++];
	m_protoType = (a << 8) | b;

	m_hardSize = pkt_data[pos++];

	m_protoSize = pkt_data[pos++];

	a = pkt_data[pos++];
	b = pkt_data[pos++];
	m_opcode = (a << 8) | b;

	m_sendMAC = parseMAC(&pos, pos + m_hardSize);

	m_sendAddr = parseIPV4(&pos, pos + m_protoSize);

	m_targetMAC = parseMAC(&pos, pos + m_hardSize);

	m_targetAddr = parseIPV4(&pos, pos + m_protoSize);
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