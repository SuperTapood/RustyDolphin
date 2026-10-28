#pragma once

#include "TCPOptions/TCPOptions.h"
#include "../../Eth/Packet.h"
#include "../../IP/IP.h"
#include "../../../../../Win/SDK.h"
#include "../../../.././../Base/ProtocolCatalog.h"
#include "../../../.././../Base/Logger.h"
#include "../../../../../Networks/capture.h"

#include <iostream>
#include <bitset>
#include <memory>

template <typename IPVersion>
class TCP : public IPVersion {
public:
	unsigned short m_srcPort;
	unsigned short m_destPort;
	unsigned int m_seqNum;
	unsigned int m_ackNum;
	unsigned char m_TCPLength;
	unsigned short m_TCPflags;
	unsigned short m_window;
	unsigned short m_TCPchecksum;
	unsigned short m_urgentPtr;
	unsigned int m_optSize;

	std::vector<std::unique_ptr<TCPOption>> m_options;

	long m_payloadLength = 0;
	std::string m_payload;

	std::string m_process;

	TCP(pcap_pkthdr* header, const u_char* pkt_data, unsigned int idx) : IPVersion(header, pkt_data, idx) {
		m_srcPort = Packet::parseShort();

		m_destPort = Packet::parseShort();

		m_seqNum = Packet::parseInt();

		m_ackNum = Packet::parseInt();

		auto len = (unsigned char)Packet::parseChar();
		auto flags = Packet::parseChar();

		m_TCPLength = (len >> 4) * 4;

		m_TCPflags = static_cast<unsigned short>(((len & 0x01) << 8) |
			static_cast<unsigned char>(flags));

		m_window = Packet::parseShort();

		m_TCPchecksum = Packet::parseShort();

		m_urgentPtr = Packet::parseShort();

		constexpr auto ETHLEN = 14;
		constexpr auto NOP = 1;
		constexpr auto MSS = 2;
		constexpr auto WSCALE = 3;
		constexpr auto SACKPERM = 4;
		constexpr auto SACK = 5;

		int total = m_TCPLength + ETHLEN + IPVersion::m_headerLength;

		m_optSize = 0;

		while (total - Packet::getPos() > 0) {
			unsigned char code = Packet::parseChar();

			std::unique_ptr<TCPOption> opt;

			switch ((int)code) {
			case NOP:
				opt = std::make_unique<TCPNOP>();
				break;
			case MSS:
				opt = std::make_unique<TCPMSS>(this);
				break;
			case WSCALE:
				opt = std::make_unique<TCPWScale>(this);
				break;
			case SACKPERM:
				opt = std::make_unique<TCPSACKPerm>(this);
				break;
			case SACK:
				opt = std::make_unique<TCPSACK>(this);
				break;
			default:
				// this gets compiled out anyway, but i felt i should keep it in
				// like a battle scar ;)
#ifdef _DEBUG
				std::stringstream ss;
				ss << "bad tcp option of code " << code << " at packet index " << idx;
				Logger::log(ss.str());
#endif
				continue;
			}

			m_optSize += opt->m_size;

			m_options.push_back(std::move(opt));
		}

		if (Packet::m_len > static_cast<unsigned int>(Packet::getPos())) {
			m_payloadLength = Packet::m_len - Packet::getPos();
			m_payload = Packet::parse(m_payloadLength);
		}

		m_process = SDK::getProcFromPort(m_srcPort);
		if (m_process.at(0) == '<' && m_process.at(m_process.size() - 1) == '>') {
			// bad process try again
			m_process = SDK::getProcFromPort(m_destPort);
		}

		Packet::m_strType = "TCP (" + Packet::m_strType + ")";
		std::stringstream ss;
		ss << "(" << m_process << ") " << m_srcPort << " -> " << m_destPort << " payload length = " << m_payloadLength;
		Packet::m_description = ss.str();

		Packet::m_expands.insert({ "TCP Title", false });
		Packet::m_expands.insert({ "TCP Flags", false });
		Packet::m_expands.insert({ "TCP Options", false });

		Packet::m_properties.insert({ "proto", "tcp" });
		Packet::m_properties.insert({ "sport", std::to_string(m_srcPort) });
		Packet::m_properties.insert({ "dport", std::to_string(m_destPort) });
		Packet::m_properties.insert({ "proc", m_process.c_str() });
	}

	~TCP() override = default;

	std::string toString() override {
		std::stringstream ss;

		ss << "TCPV4 Packet at " << Packet::m_texts["time"] << " from " << IPVersion::m_srcAddr << " at port " << m_srcPort << " to " << IPVersion::m_destAddr << " at port " << m_destPort;

		if (m_options.size() > 0) {
			ss << " with options : (";
			for (const auto& o : m_options) {
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
		j["Number of Options"] = m_options.size();

		std::stringstream ss;
		for (const auto& o : m_options) {
			ss << o->toString() << ", ";
		}

		j["TCP Options"] = ss.str();
		j["Payload Length"] = m_payloadLength;
		j["Payload"] = m_payload;

		return j;
	}
std::map<std::string, std::string> getTexts() {
		if (Packet::m_texts.empty()) {
			IPVersion::getTexts();

			Packet::m_texts["TCP Title"] = std::format("Transmission Control Protocol, Src Port: {}, Dst Port: {}, Seq: {}, Len: {}", m_srcPort, m_destPort, m_seqNum, m_payloadLength);

			Packet::m_texts["SPort"] = std::format("\tSource Port: {}", m_srcPort);

			Packet::m_texts["DPort"] = std::format("\tDestination Port: {}", m_destPort);

			Packet::m_texts["SeqNum"] = std::format("\tSequence Number: {}", m_seqNum);

			Packet::m_texts["AckNum"] = std::format("\tAcknowledgement Number: {}", m_ackNum);

			Packet::m_texts["HeaderLen"] = std::format("\t{}  . . . . = Header Length: {} bytes ({})", std::bitset<4>(m_TCPLength).to_string(), (int)m_TCPLength, ((int)m_TCPLength / 4));

			auto flagBits = std::bitset<12>(m_TCPflags).to_string();
			std::stringstream ss;

			static std::array<std::string, 9> flagNames = {
				"Accurate ECN",
				"Congestion Window Reduced",
				"ECN-Echo",
				"Urgent",
				"Acknowledgement",
				"Push",
				"Reset",
				"Syn",
				"Fin",
			};

			for (int i = 0; i < 9; i++) {
				std::string base = ". . . .  . . . .  . . . .";
				if (flagBits[i + 3] == '1') {
					ss << ProtocolCatalog::TCPFlags[i + 1] << ", ";
				}

				auto idx = i + 3;
				auto group = (idx / 4);

				base[idx * 2 + group] = flagBits[i + 3];

				Packet::m_texts[ProtocolCatalog::TCPFlags[i + 1]] = std::format("\t\t{} = {}: {}", base, flagNames[i], flagBits[idx] == '1' ? "Set" : "Not Set");
			}

			Packet::m_texts["RES"] = std::format("\t\t{} .  . . . .  . . . . = Reserved: {}", flagBits.substr(0, 3), flagBits.starts_with("000") ? "Not Set" : "Set");

			Packet::m_texts["TCPFlags"] = std::format("   Flags: 0x{:03x} ({})", m_TCPflags, ss.str());

			Packet::m_texts["TCPWindow"] = std::format("\tWindow: {}", m_window);

			Packet::m_texts["TCPChecksum"] = std::format("\tChecksum: 0x{:x}", m_TCPchecksum);

			Packet::m_texts["UrgentPtr"] = std::format("\tUrgent Pointer: {}", m_urgentPtr);

			Packet::m_texts["OptionTitle"] = std::format("   Options: ({} bytes)", m_optSize);
		}

		return Packet::m_texts;
	}
};
