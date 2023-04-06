#include "IPV6.h"

#include <sstream>

IPV6::IPV6(pcap_pkthdr* header, const u_char* pkt_data) : Packet(header, pkt_data) {
	version = pkt_data[pos] & 0x11110000;
	trafficCls = ((pkt_data[pos] & 0x00001111) << 4) | (pkt_data[pos + 1] & 0x11110000);
	pos += 2;

	flowLabel = (((pkt_data[pos] & 0x00001111) << 16) | (pkt_data[pos + 1] << 8)) | pkt_data[pos + 2];

	pos += 3;

	payloadLength = parseLong(&pos, pos + 2);

	proto = pkt_data[pos++];

	hopLimit = pkt_data[pos++];

	srcAddr = parseIPV6(&pos, pos + 16);

	destAddr = parseIPV6(&pos, pos + 16);
}

std::string IPV6::toString() {
	std::stringstream ss;

	ss << "IPV6 Packet at " << m_time << " of length " << payloadLength << " from " << srcAddr << " to " << destAddr << " transfer protocol is " << proto;

	return ss.str();
}