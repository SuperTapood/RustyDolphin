#pragma once

#include "../../Eth/Packet.h"
#include "../../IP/IP.h"
#include <pcap.h>
#include <uchar.h>
#include "../../../../../GUI/Renderer.h"
#include <type_traits>

class ICMP : public IPV4 {
public:
	unsigned short m_ICMPtype;
	unsigned short m_code;
	unsigned short m_ICMPChecksum;
	unsigned short m_indentifierBE;
	unsigned short m_indentifierLE;
	unsigned short m_seqNumberBE;
	unsigned short m_seqNumberLE;
	unsigned long long m_ROHLength;
	std::string m_typeDesc;
	std::string m_restOfHeader;

	ICMP(pcap_pkthdr* header, const u_char* pkt_data, unsigned int idx) : IPV4(header, pkt_data, idx) {
		m_ICMPtype = parseChar();
		m_code = parseChar();
		m_ICMPChecksum = Packet::parseShort();
		m_indentifierBE = Packet::parseShort();
		m_indentifierLE = htons(m_indentifierBE);
		m_seqNumberBE = Packet::parseShort();
		m_seqNumberLE = htons(m_seqNumberBE);
		m_ROHLength = Packet::m_len - getPos();
		m_restOfHeader = Packet::parse(m_ROHLength);

		Packet::m_strType = "ICMP (" + Packet::m_strType + ")";
		std::stringstream ss;

		switch (m_ICMPtype) {
		case 0:
			ss << "Echo (ping) reply";
			break;
		case 8:
			ss << "Echo (ping) request";
			break;
		default:
			ss << "Unknown code " << m_ICMPtype;
			break;
		}

		m_typeDesc = ss.str();

		ss << " len = " << m_ROHLength << " TTL = " << (int)IPV4::m_ttl;

		m_description = ss.str();

		m_expands.insert({ "ICMP Title", false });
		m_expands.insert({ "ICMP Data", false });
	}

	std::string toString() override {
		std::stringstream ss;

		ss << "ICMPV4 packet at " << Packet::m_texts["time"] << " of type " << m_ICMPtype << " of code " << m_code << " (with checksum " << m_ICMPChecksum << " and rest of header is " << m_restOfHeader << ")\n";

		return ss.str();
	}

	json jsonify() override {
		auto j = jsonify();

		j["ICMP"] = "start";
		j["Type"] = m_ICMPtype;
		j["Code"] = m_code;
		j["ICMP Checksum"] = m_ICMPChecksum;
		j["Indentifier BE"] = m_indentifierBE;
		j["Indentifier LE"] = m_indentifierLE;
		j["Sequence Number BE"] = m_seqNumberBE;
		j["Sequence Number LE"] = m_seqNumberLE;
		j["ROH Length"] = m_ROHLength;
		j["The Rest of the Header"] = m_restOfHeader;

		return j;
	}

	void render() override {
		Renderer::render(this);
	}

	void renderExpanded() override {
		Renderer::renderExpanded(this);
	}

	std::map<std::string, std::string> getTexts() override {
		if (Packet::m_texts.empty()) {
			IPV4::getTexts();

			m_texts["ICMPType"] = std::format("\tType: {} ({})", m_ICMPtype, m_typeDesc);

			m_texts["ICMPCode"] = std::format("\tCode: {}", m_code);

			m_texts["ICMPChecksum"] = std::format("\tChecksum: 0x{:x}", m_ICMPChecksum);

			m_texts["IDBE"] = std::format("\tIdentifier (BE): {} (0x{:x})", m_indentifierBE, m_indentifierBE);

			m_texts["IDLE"] = std::format("\tIdentifier (LE): {} (0x{:x})", m_indentifierLE, m_indentifierLE);

			m_texts["SNBE"] = std::format("\tSequence Number (BE): {} (0x{:x})", m_seqNumberBE, m_seqNumberBE);

			m_texts["SNLE"] = std::format("\tSequence Number (LE): {} (0x{:x})", m_seqNumberLE, m_seqNumberLE);

			m_texts["ICMPDataHeader"] = std::format("   Data ({} bytes)", m_ROHLength);

			m_texts["ICMPData"] = std::format("\t\tData: {}", m_restOfHeader);
		}

		return Packet::m_texts;
	}
};