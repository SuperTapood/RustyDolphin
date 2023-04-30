#include "IPV6.h"

#include <sstream>

IPV6::IPV6(pcap_pkthdr* header, const u_char* pkt_data) : Packet(header, pkt_data) {
	auto thingy = parseLong();
	m_trafficCls = thingy & 4080;

	m_flowLabel = thingy & 1048575;

	m_payloadLength = parseInt();

	m_nextHeader = pkt_data[pos++];

	m_hopLimit = pkt_data[pos++];

	m_srcAddr = parseIPV6();

	m_destAddr = parseIPV6();
}

std::string IPV6::toString() {
	std::stringstream ss;

	ss << "IPV6 Packet at " << m_time << " of length " << m_payloadLength << " from " << m_srcAddr << " to " << m_destAddr << "of payload length: " << m_payloadLength << " transfer protocol is " << m_nextHeader << "\n";

	return ss.str();
}

json IPV6::jsonify() {
	auto j = Packet::jsonify();

	j["IPV6"] = "start";
	j["Version"] = m_version;
	j["Traffic Class"] = m_trafficCls;
	j["Flow Label"] = m_flowLabel;
	j["Payload Length"] = m_payloadLength;
	j["Protocol"] = m_nextHeader;
	j["Hop Limit"] = m_hopLimit;
	j["Source Address"] = m_srcAddr;
	j["Destination Address"] = m_destAddr;
	j["Header Length"] = m_headerLength;

	return j;
}