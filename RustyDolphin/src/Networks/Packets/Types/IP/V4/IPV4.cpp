#include "IPV4.h"

#include <sstream>

IPV4::IPV4(pcap_pkthdr* header, const u_char* pkt_data) : Packet(header, pkt_data) {
	headerLength = (int)pkt_data[14];
	differServ = (int)pkt_data[15];

	auto a = pkt_data[16];
	auto b = pkt_data[17];

	totalLength = (a << 8) | b;

	a = pkt_data[18];
	b = pkt_data[19];

	identification = (a << 8) | b;

	flags = pkt_data[20];
	fragmentationOffset = pkt_data[21];

	ttl = pkt_data[22];

	proto = pkt_data[23];

	a = pkt_data[24];
	b = pkt_data[25];
	headerChecksum = (a << 8) | b;

	srcAddr = parseIPV4(26, 30);
	destAddr = parseIPV4(30, 34);
}

std::string IPV4::toString() {
	std::stringstream ss;

	ss << "IPV4 Packet at " << time << " of length " << totalLength << " from " << srcAddr << " to " << destAddr << " transfer protocol is " << proto;

	return ss.str();
}