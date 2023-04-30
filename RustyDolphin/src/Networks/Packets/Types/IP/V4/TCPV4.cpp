#include "TCPV4.h"

#include "../../TCPOptions/TCPOptions.h"
#include "../../../../../Base/Logger.h"
#include "../../../../../Networks/Capture.h"
#include "../../src/Win/Win.h"
#include <iostream>

#include <vector>

TCPV4::TCPV4(pcap_pkthdr* header, const u_char* pkt_data) : IPV4(header, pkt_data) {
	m_srcPort = (int)parseLong(&pos, pos + 2);

	m_destPort = (int)parseLong(&pos, pos + 2);

	m_seqNum = parseLong(&pos, pos + 4);

	m_ackNum = parseLong(&pos, pos + 4);

	m_TCPLength = (pkt_data[pos] >> 4) * 4;

	m_TCPflags = (pkt_data[pos] & 0x0F) | pkt_data[pos + 1];

	pos += 2;

	m_window = (int)parseLong(&pos, pos + 2);

	m_TCPchecksum = (int)parseLong(&pos, pos + 2);

	m_urgentPtr = (int)parseLong(&pos, pos + 2);

	constexpr auto ETHLEN = 14;
	constexpr auto NOP = 1;
	//constexpr auto MSS = 2;
	//constexpr auto WSCALE = 3;
	//constexpr auto SACKPERM = 4;
	constexpr auto SACK = 5;
	//constexpr auto TIMESTAMPS = 8;

	int total = m_TCPLength + ETHLEN + m_headerLength;
	m_optionCount = 0;
	std::vector<TCPOption*> vec;

	while (total - pos > 0) {
		int code = pkt_data[pos++];
		m_optionCount++;

		switch (code) {
		case NOP:
			vec.push_back(new TCPNOP());
			break;
		case SACK:
			vec.push_back(new TCPSACK(header, pkt_data, &pos));
			break;
		default:
#ifdef _DEBUG
			std::stringstream ss;
			ss << "bad option of packet data: " << code;
			Logger::log(ss.str());
			Capture::dump(header, pkt_data);
			m_optionCount--;
			exit(code);
#endif
			break;
		}
	}

	m_options = new TCPOption * [vec.size()];

	for (size_t i = 0; i < vec.size(); i++) {
		m_options[i] = vec[i];
	}

	if (Packet::m_len > pos) {
		m_payloadLength = Packet::m_len - pos;
		m_payload = parse(m_payloadLength);
	}
}

std::string TCPV4::toString() {
	std::stringstream ss;

	ss << "TCPV4 Packet at " << m_time << " from " << m_srcAddr << " at port " << m_srcPort << " to " << m_destAddr << " at port " << m_destPort;

	if (m_optionCount > 0) {
		ss << " with options : (";
		for (int i = 0; i < m_optionCount; i++) {
			auto o = m_options[i];
			ss << o->toString() << ", ";
		}
		ss << ")";
	}

	ss << ". Proccess = ";

	auto proc = SDK::getProcFromPort(m_srcPort);

	if (proc == "<UNKNOWN>") {
		proc = SDK::getProcFromPort(m_destPort);
	}

	ss << proc << "\n";

	return ss.str();
}

json TCPV4::jsonify() {
	auto j = IPV4::jsonify();

	j["TCPV4"] = "start";
	j["Source Port"] = m_srcPort;
	j["Destination Port"] = m_destPort;
	j["Sequence Number"] = m_seqNum;
	j["Acknoledgement Number"] = m_ackNum;
	j["TCP Header Length"] = m_TCPLength;
	j["TCP Flags"] = m_TCPflags;
	j["Window"] = m_window;
	j["TCP Checksum"] = m_TCPchecksum;
	j["Urgent Pointer"] = m_urgentPtr;
	j["Number of Options"] = m_optionCount;

	std::stringstream ss;
	for (int i = 0; i < m_optionCount; i++) {
		auto o = m_options[i];
		ss << o->toString() << ", ";
	}

	j["TCP Options"] = ss.str();
	j["Payload Length"] = m_payloadLength;
	j["Payload"] = m_payload;

	return j;
}