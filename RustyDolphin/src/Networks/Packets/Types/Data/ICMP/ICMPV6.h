#pragma once

#include "../../Eth/Packet.h"
#include "../../IP/IP.h"
#include <pcap.h>
#include <uchar.h>
#include "../../../../../GUI/Renderer.h"
#include <type_traits>

#include "ICMPV6Types/ICMPV6Types.h"

class ICMPV6 : public IPV6 {
public:
	ICMPV6Type* m_ICMPV6Type;
	unsigned short m_ICMPV6Checksum;
	unsigned long long m_messageLength;
	std::string m_messageBody;

	ICMPV6(pcap_pkthdr* header, const u_char* pkt_data, unsigned int idx) : IPV6(header, pkt_data, idx) {
		m_ICMPV6Type = new ICMPV6Type(this);
		m_ICMPV6Checksum = Packet::parseShort();
		m_messageLength = IPV6::m_payloadLength - 4;
		m_messageBody = parse(m_messageLength);

		Packet::m_strType = "ICMPV6";

		Packet::m_description = std::format("{} of code = {} len = {} hop limit = {}", m_ICMPV6Type->m_typeStr, m_ICMPV6Type->m_codeStr, m_messageLength, (int)IPV6::m_hopLimit);

		m_expands.insert({ "ICMPV6 Title", false });
		Packet::m_properties.insert({ "proto", "icmpv6" });
	}

	std::string toString() override {
		std::stringstream ss;

		ss << "ICMPV4 packet at " << Packet::m_texts["time"] << " of type " << (int)m_ICMPV6Type->m_type << " of code " << (int)m_ICMPV6Type->m_code << " (with checksum " << m_ICMPV6Checksum << ")\n";

		return ss.str();
	}

	json jsonify() override {
		auto j = IPV6::jsonify();

		j["ICMP"] = "start";
		j["Type"] = (int)m_ICMPV6Type->m_type;
		j["Code"] = (int)m_ICMPV6Type->m_code;
		j["ICMP Checksum"] = m_ICMPV6Checksum;
		j["length of message"] = m_messageLength;
		j["message"] = m_messageBody;

		return j;
	}

	void render() override {
		Renderer::render(this);
	}

	void renderExpanded() override {
		Renderer::renderExpanded(this);
	}

	std::map<std::string, std::string> getTexts() {
		if (m_texts.empty()) {
			IPV6::getTexts();

			m_texts["ICMPV6Type"] = std::format("\tType: {} ({})", m_ICMPV6Type->m_typeStr, m_ICMPV6Type->m_type);

			m_texts["ICMPV6Code"] = std::format("\tCode: {} ({})", m_ICMPV6Type->m_codeStr, m_ICMPV6Type->m_code);

			m_texts["ICMPV6Checksum"] = std::format("\tChecksum: {:x}", m_ICMPV6Checksum);

			m_texts["ICMPV6Length"] = std::format("\tLength of the Message: {}", m_messageLength);

			m_texts["ICMPV6Message"] = std::format("\tThe Message: {}", m_messageBody);
		}

		return Packet::m_texts;
	}
};