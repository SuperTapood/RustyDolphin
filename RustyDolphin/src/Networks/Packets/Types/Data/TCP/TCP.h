#pragma once

#include "TCPOptions/TCPOptions.h"
#include "../../Eth/Packet.h"
#include "../../IP/IP.h"
#include "../../../src/Networks/capture.h"
#include "../../../src/Win/SDK.h"

template <typename IPVersion>
class TCP : public IPVersion {
	static_assert(std::is_base_of_v<Packet, IPVersion>,
		"IPVersion must inherit from Packet");
public:
	int m_srcPort;
	int m_destPort;
	long m_seqNum;
	long m_ackNum;
	char m_TCPLength;
	int m_TCPflags;
	int m_window;
	int m_TCPchecksum;
	int m_urgentPtr;

	int m_optionCount;
	TCPOption** m_options;

	long m_payloadLength;
	std::string m_payload;

	TCP(pcap_pkthdr* header, const u_char* pkt_data) : IPVersion(header, pkt_data) {
		m_srcPort = Packet::parseInt();

		m_destPort = Packet::parseInt();

		m_seqNum = Packet::parseLong();

		m_ackNum = Packet::parseLong();

		m_TCPLength = (pkt_data[Packet::pos] >> 4) * 4;

		m_TCPflags = (pkt_data[Packet::pos] & 0x0F) | pkt_data[Packet::pos + 1];

		Packet::pos += 2;

		m_window = Packet::parseInt();

		m_TCPchecksum = Packet::parseInt();

		m_urgentPtr = Packet::parseInt();

		constexpr auto ETHLEN = 14;
		constexpr auto NOP = 1;
		//constexpr auto MSS = 2;
		//constexpr auto WSCALE = 3;
		//constexpr auto SACKPERM = 4;
		constexpr auto SACK = 5;
		//constexpr auto TIMESTAMPS = 8;

		int total = m_TCPLength + ETHLEN + IPVersion::m_headerLength;
		m_optionCount = 0;
		std::vector<TCPOption*> vec;

		while (total - Packet::pos > 0) {
			int code = pkt_data[Packet::pos++];
			m_optionCount++;

			switch (code) {
			case NOP:
				vec.push_back(new TCPNOP());
				break;
			case SACK:
				vec.push_back(new TCPSACK(header, pkt_data, &(IPVersion::pos)));
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

		if (Packet::m_len > IPVersion::pos) {
			m_payloadLength = Packet::m_len - IPVersion::pos;
			m_payload = IPVersion::parse(m_payloadLength);
		}
	}

	std::string toString() override {
		std::stringstream ss;

		ss << "TCPV4 Packet at " << IPVersion::m_time << " from " << IPVersion::m_srcAddr << " at port " << m_srcPort << " to " << IPVersion::m_destAddr << " at port " << m_destPort;

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

	json jsonify() override {
		auto j = IPVersion::jsonify();

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
};