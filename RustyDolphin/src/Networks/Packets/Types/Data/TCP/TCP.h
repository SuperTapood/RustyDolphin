#pragma once

#include "TCPOptions/TCPOptions.h"
#include "../../Eth/Packet.h"
#include "../../IP/IP.h"
#include "../../../src/Networks/capture.h"
#include "../../../src/Win/SDK.h"
#include "../../../../../GUI/Renderer.h"

#include <iostream>

template <typename IPVersion>
class TCP : public IPVersion {
	static_assert(std::is_base_of_v<Packet, IPVersion>,
		"IPVersion must inherit from Packet");
public:
	unsigned short m_srcPort;
	unsigned short m_destPort;
	unsigned int m_seqNum;
	unsigned int m_ackNum;
	char m_TCPLength;
	short m_TCPflags;
	short m_window;
	short m_TCPchecksum;
	short m_urgentPtr;

	int m_optionCount;
	TCPOption** m_options;

	long m_payloadLength;
	std::string m_payload;

	std::string m_process;

	std::string m_TCPTitle;

	TCP(pcap_pkthdr* header, const u_char* pkt_data, unsigned int idx) : IPVersion(header, pkt_data, idx) {
		m_srcPort = Packet::parseShort();

		m_destPort = Packet::parseShort();

		m_seqNum = Packet::parseInt();

		m_ackNum = Packet::parseInt();

		auto len = Packet::parseShort();
		auto flags = Packet::parseChar();

		m_TCPLength = (len >> 4) * 4;

		m_TCPflags = (len & 0x0F) | flags;

		m_window = Packet::parseShort();

		m_TCPchecksum = Packet::parseShort();

		m_urgentPtr = Packet::parseShort();

		constexpr auto ETHLEN = 14;
		constexpr auto NOP = 1;
		constexpr auto MSS = 2;
		constexpr auto WSCALE = 3;
		constexpr auto SACKPERM = 4;
		constexpr auto SACK = 5;
		constexpr auto TIMESTAMPS = 8;

		int total = m_TCPLength + ETHLEN + IPVersion::m_headerLength;
		m_optionCount = 0;
		std::vector<TCPOption*> vec;

		while (total - Packet::getPos() > 0) {
			int code = Packet::parseChar();
			m_optionCount++;

			switch (code) {
			case NOP:
				vec.push_back(new TCPNOP());
				break;
			case MSS:
				vec.push_back(new TCPMSS(this));
				break;
			case WSCALE:
				vec.push_back(new TCPWScale(this));
				break;
			case SACKPERM:
				vec.push_back(new TCPSACKPerm(this));
				break;
			case SACK:
				vec.push_back(new TCPSACK(this));
				break;
			default:
#ifdef _DEBUG
				std::stringstream ss;
				ss << "bad tcp option of code " << code << " at packet index " << idx;
				Logger::log(ss.str());
				// Capture::dump(header, pkt_data);
				m_optionCount--;
				// exit(code);
#endif
				break;
			}
		}

		m_options = new TCPOption * [vec.size()];

		for (size_t i = 0; i < vec.size(); i++) {
			m_options[i] = vec[i];
		}

		if (Packet::m_len > Packet::getPos()) {
			m_payloadLength = Packet::m_len - Packet::getPos();
			m_payload = Packet::parse(m_payloadLength);
		}

		//if constexpr (std::is_same_v<IPVersion, IPV4>) {
		//	/*if (IPVersion::m_srcAddr == SDK::ipAddress) {
		//		m_process = SDK::getProcFromPort(m_srcPort);
		//	}
		//	else {
		//		m_process = SDK::getProcFromPort(m_destPort);
		//	}*/
		//	m_process = SDK::getProcFromPort(m_srcPort);
		//	if (m_process.at(0) == '<' && m_process.at(m_process.size() - 1) == '>') {
		//		m_process = SDK::getProcFromPort(m_destPort);
		//	}
		//}
		//else if constexpr (std::is_same_v<IPVersion, IPV6>) {
		//	m_process = SDK::getProcFromPort(m_srcPort);
		//	if (m_process.at(0) == '<' && m_process.at(m_process.size() - 1) == '>') {
		//		m_process = SDK::getProcFromPort(m_destPort);
		//	}
		//}

		m_process = SDK::getProcFromPort(m_srcPort);
		if (m_process.at(0) == '<' && m_process.at(m_process.size() - 1) == '>') {
			m_process = SDK::getProcFromPort(m_destPort);
		}

		Packet::m_strType = "TCP (" + Packet::m_strType + ")";
		std::stringstream ss;
		ss << "(" << m_process << ") " << m_srcPort << " -> " << m_destPort << " payload length = " << m_payloadLength;
		Packet::m_description = ss.str();

		Packet::m_expands.insert({ "TCP Title", false });

		m_TCPTitle = std::format("Transmission Control Protocol, Src Port: {}, Dst Port: {}, Seq: {}, Len: {}", m_srcPort, m_destPort, m_seqNum, m_payloadLength);
	}

	std::string toString() override {
		std::stringstream ss;

		ss << "TCPV4 Packet at " << Packet::m_texts["time"] << " from " << IPVersion::m_srcAddr << " at port " << m_srcPort << " to " << IPVersion::m_destAddr << " at port " << m_destPort;

		if (m_optionCount > 0) {
			ss << " with options : (";
			for (int i = 0; i < m_optionCount; i++) {
				auto o = m_options[i];
				ss << o->toString() << ", ";
			}
			ss << ")";
		}

		ss << ". Proccess = " << m_process << ".\n";

		return ss.str();
	}

	json jsonify() override {
		auto j = IPVersion::jsonify();

		j["TCP"] = "start";
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

	void render() override {
		Renderer::render(this);
	}

	void renderExpanded() override {
		Renderer::renderExpanded(this);
	}
};