#include "IPV6.h"

#include <sstream>

IPV6::IPV6(pcap_pkthdr* header, const u_char* pkt_data) : Packet(header, pkt_data) {
	m_version = pkt_data[pos] & 0x11110000;
	m_trafficCls = ((pkt_data[pos] & 0x00001111) << 4) | (pkt_data[pos + 1] & 0x11110000);
	pos += 2;

	m_flowLabel = (((pkt_data[pos] & 0x00001111) << 16) | (pkt_data[pos + 1] << 8)) | pkt_data[pos + 2];

	pos += 2;

	m_payloadLength = parseLong(&pos, pos + 2);

	m_proto = pkt_data[pos++];

	m_hopLimit = pkt_data[pos++];

	m_srcAddr = parseIPV6(&pos, pos + 16);

	m_destAddr = parseIPV6(&pos, pos + 16);
}

std::string IPV6::toString() {
	std::stringstream ss;

	ss << "IPV6 Packet at " << m_time << " of length " << m_payloadLength << " from " << m_srcAddr << " to " << m_destAddr << "of payload length: " << m_payloadLength << " transfer protocol is " << m_proto << "\n";

	return ss.str();
}

json IPV6::jsonify() {
	auto j = Packet::jsonify();

	j["IPV6"] = "start";
	j["Version"] = m_version;
	j["Traffic Class"] = m_trafficCls;
	j["Flow Label"] = m_flowLabel;
	j["Payload Length"] = m_payloadLength;
	j["Protocol"] = m_proto;
	j["Hop Limit"] = m_hopLimit;
	j["Source Address"] = m_srcAddr;
	j["Destination Address"] = m_destAddr;
	j["Header Length"] = m_headerLength;

	return j;
}