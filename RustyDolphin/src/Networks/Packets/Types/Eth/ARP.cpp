#include "ARP.h"

#include <sstream>


ARP::ARP(pcap_pkthdr* header, const u_char* pkt_data) : Packet(header, pkt_data) {
	auto a = pkt_data[14];
	auto b = pkt_data[15];
	hardType = (a << 8) | b;

	a = pkt_data[16];
	b = pkt_data[17];
	protoType = (a << 8) | b;

	hardSize = pkt_data[18];

	protoSize = pkt_data[19];

	a = pkt_data[20];
	b = pkt_data[21];
	opcode = (a << 8) | b;

	sendMAC = parseMAC(22, 28);
	sendAddr = parseIPV4(28, 28 + protoSize);
	targetMAC = parseMAC(28 + protoSize, 34 + protoSize);
	targetAddr = parseIPV4(34 + protoSize, 34 + (protoSize * 2));
}

std::string ARP::toString() {
	std::stringstream ss;

	ss << "ARP Packet at " << time;

	if (opcode == 1) {
		ss << " who tf is " << targetAddr << "? Tell " << sendAddr;
	}
	else if (opcode == 2) {
		ss << sendAddr << " is at physical address " << sendMAC;
	}
	else {
		ss << "unknown opcode " << opcode;
	}

	return ss.str();
}