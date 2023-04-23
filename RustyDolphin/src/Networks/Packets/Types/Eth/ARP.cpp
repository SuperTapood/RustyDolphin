#include "ARP.h"

#include <sstream>

ARP::ARP(pcap_pkthdr* header, const u_char* pkt_data) : Packet(header, pkt_data) {
	auto a = pkt_data[pos++];
	auto b = pkt_data[pos++];
	hardType = (a << 8) | b;

	a = pkt_data[pos++];
	b = pkt_data[pos++];
	protoType = (a << 8) | b;

	hardSize = pkt_data[pos++];

	protoSize = pkt_data[pos++];

	a = pkt_data[pos++];
	b = pkt_data[pos++];
	opcode = (a << 8) | b;

	sendMAC = parseMAC(&pos, pos + hardSize);

	sendAddr = parseIPV4(&pos, pos + protoSize);

	targetMAC = parseMAC(&pos, pos + hardSize);

	targetAddr = parseIPV4(&pos, pos + protoSize);
}

std::string ARP::toString() {
	return "";
	std::stringstream ss;

	ss << "ARP Packet at " << m_time;

	if (opcode == 1) {
		ss << " who tf is " << targetAddr << "? Tell " << sendAddr;
	}
	else if (opcode == 2) {
		ss << " " << sendAddr << " is at physical address " << sendMAC;
	}
	else {
		ss << " unknown opcode " << opcode;
	}

	ss << "\n";

	return ss.str();
}