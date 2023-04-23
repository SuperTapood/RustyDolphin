#include "IPV6.h"

#include <sstream>

IPV6::IPV6(pcap_pkthdr* header, const u_char* pkt_data) : Packet(header, pkt_data) {
	version = pkt_data[pos] & 0x11110000;
	trafficCls = ((pkt_data[pos] & 0x00001111) << 4) | (pkt_data[pos + 1] & 0x11110000);
	pos += 2;

	flowLabel = (((pkt_data[pos] & 0x00001111) << 16) | (pkt_data[pos + 1] << 8)) | pkt_data[pos + 2];

	pos += 2;

	payloadLength = parseLong(&pos, pos + 2);

	proto = pkt_data[pos++];

	hopLimit = pkt_data[pos++];

	srcAddr = parseIPV6(&pos, pos + 16);

	destAddr = parseIPV6(&pos, pos + 16);
}

std::string IPV6::toString() {
	std::stringstream ss;

	ss << "IPV6 Packet at " << m_time << " of length " << payloadLength << " from " << srcAddr << " to " << destAddr << "of payload length: " << payloadLength << " transfer protocol is " << proto << "\n";

	return ss.str();
}

json IPV6::jsonify() {
	auto j = Packet::jsonify();

	j["IPV6"] = "start";
	j["Version"] = version;
	j["Traffic Class"] = trafficCls;
	j["Flow Label"] = flowLabel;
	j["Payload Length"] = payloadLength;
	j["Protocol"] = proto;
	j["Hop Limit"] = hopLimit;
	j["Source Address"] = srcAddr;
	j["Destination Address"] = destAddr;
	j["Header Length"] = headerLength;

	return j;
}