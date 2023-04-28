#include "IPV4.h"

#include <sstream>
#include <vector>
#include "../../../../../Base/Logger.h"
#include "../../../../Capture.h"
#include <iostream>

IPV4::IPV4(pcap_pkthdr* header, const u_char* pkt_data) : Packet(header, pkt_data) {
	auto start = pos;
	m_headerLength = ((int)pkt_data[pos++] & 0xF) * 4;
	m_differServ = (int)pkt_data[pos++];

	m_totalLength = (int)parseLong(&pos, pos + 2);

	m_identification = (int)parseLong(&pos, pos + 2);

	m_flags = pkt_data[pos++];

	m_fragmentationOffset = pkt_data[pos++];

	m_ttl = pkt_data[pos++];

	m_proto = pkt_data[pos++];

	m_headerChecksum = (int)parseLong(&pos, pos + 2);

	// proto size is 4 :)
	m_srcAddr = parseIPV4(&pos, pos + 4);

	m_destAddr = parseIPV4(&pos, pos + 4);

	int diff = (m_headerLength + start) - pos;

	m_IPoptionsCount = 0;
	std::vector<IPV4Option> vec;

	while (diff > 0) {
		std::cout << "send help " << std::endl;
		m_IPoptionsCount++;
		auto temp = pos;

		int code = pkt_data[pos] & 31;

		constexpr auto routerAlert = 20;

		switch (code) {
		case routerAlert:
			vec.push_back(RouterAlert(header, pkt_data, &pos));
			break;
		default:
#ifdef _DEBUG
			std::stringstream ss;
			ss << "bad ip option of packet data: " << code;
			Logger::log(ss.str());
			Capture::dump(header, pkt_data);
			pos += diff;
			diff = 0;
#endif
			break;
		}

		diff -= (pos - temp);
	}

	if (diff > 0) {
		m_opts = (IPV4Option*)malloc(sizeof(IPV4Option) * m_IPoptionsCount);

		std::copy(vec.begin(), vec.end(), m_opts);
	}
}

std::string IPV4::toString() {
	std::stringstream ss;

	ss << "IPV4 Packet at " << m_time << " of length " << m_totalLength << " from " << m_srcAddr << " to " << m_destAddr << " transfer protocol is " << m_proto << " with options: ";

	for (int i = 0; i < m_IPoptionsCount; i++) {
		ss << m_opts[i].toString() << ", ";
	}

	ss << "\n";

	return ss.str();
}

json IPV4::jsonify() {
	auto j = Packet::jsonify();

	j["IPV4"] = "start";
	j["IPV4 Header Length"] = m_headerLength;
	j["Differentiated Services"] = m_differServ;
	j["Total Length"] = m_totalLength;
	j["Identification"] = m_identification;
	j["Flags"] = m_flags;
	j["Fragmentation Offset"] = m_fragmentationOffset;
	j["Time to Live"] = m_ttl;
	j["protocol"] = m_proto;
	j["IPV4 Checksum"] = m_headerChecksum;
	j["Source Address"] = m_srcAddr;
	j["Destination Address"] = m_destAddr;
	j["IP Options Count"] = m_IPoptionsCount;

	std::stringstream ss;
	for (int i = 0; i < m_IPoptionsCount; i++) {
		ss << m_opts[i].toString() << ", ";
	}
	j["IP Options"] = ss.str();

	return j;
}