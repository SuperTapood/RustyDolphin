#include "TCPV4.h"

#include "../../TCPOptions/TCPOptions.h"
#include "../../../../../Base/Logger.h"
#include "../../../../../Networks/Capture.h"
#include <iostream>

#include <vector>

TCPV4::TCPV4(pcap_pkthdr* header, const u_char* pkt_data) : IPV4(header, pkt_data) {
	srcPort = (int)parseLong(&pos, pos + 2);

	destPort = (int)parseLong(&pos, pos + 2);

	seqNum = parseLong(&pos, pos + 4);

	ackNum = parseLong(&pos, pos + 4);

	TCPLength = (pkt_data[pos] >> 4) * 4;

	TCPflags = (pkt_data[pos] & 0x0F) | pkt_data[pos + 1];

	pos += 2;

	window = (int)parseLong(&pos, pos + 2);

	TCPchecksum = (int)parseLong(&pos, pos + 2);

	urgentPtr = (int)parseLong(&pos, pos + 2);

	constexpr auto ETHLEN = 14;
	constexpr auto NOP = 1;
	//constexpr auto MSS = 2;
	//constexpr auto WSCALE = 3;
	//constexpr auto SACKPERM = 4;
	constexpr auto SACK = 5;
	//constexpr auto TIMESTAMPS = 8;

	int total = TCPLength + ETHLEN + headerLength;
	optionCount = 0;
	std::vector<TCPOption*> vec;

	while (total - pos > 0) {
		int code = pkt_data[pos++];
		optionCount++;

		switch (code) {
		case NOP:
			vec.push_back(new TCPNOP());
			break;
		case SACK:
			vec.push_back(new TCPSACK(header, pkt_data, &pos));
			break;
		default:
			Logger::log("bad option of packet data");
			Capture::dump(header, pkt_data);
			optionCount--;
			exit(code);
			break;
		}
	}

	options = new TCPOption * [vec.size()];

	for (size_t i = 0; i < vec.size(); i++) {
		options[i] = vec[i];
	}
}

std::string TCPV4::toString() {
	std::stringstream ss;

	ss << "TCPV4 Packet at " << m_time << " from " << srcAddr << " at port " << srcPort << " to " << destAddr << " at port " << destPort << " with options: (";

	for (int i = 0; i < optionCount; i++) {
		auto o = options[i];
		ss << o->toString() << ", ";
	}

	ss << ")\n";

	return ss.str();
}

json TCPV4::jsonify() {
	auto j = IPV4::jsonify();

	j["TCPV4"] = "start";
	j["Source Port"] = srcPort;
	j["Destination Port"] = destPort;
	j["Sequence Number"] = seqNum;
	j["Acknoledgement Number"] = ackNum;
	j["TCP Header Length"] = TCPLength;
	j["TCP Flags"] = TCPflags;
	j["Window"] = window;
	j["TCP Checksum"] = TCPchecksum;
	j["Urgent Pointer"] = urgentPtr;
	j["Number of Options"] = optionCount;

	std::stringstream ss;
	for (int i = 0; i < optionCount; i++) {
		auto o = options[i];
		ss << o->toString() << ", ";
	}

	j["TCP Options"] = ss.str();

	return j;
}