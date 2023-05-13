#pragma once

#include "../../Eth/Packet.h"
#include "../../IP/IP.h"
#include <pcap.h>
#include <uchar.h>
#include "../../../../../GUI/Renderer.h"
#include <type_traits>

class ICMPV6 : public IPV6 {
public:
	unsigned short m_ICMPV6type;
	unsigned short m_code;
	unsigned short m_ICMPV6Checksum;
	unsigned long long m_messageLength;
	std::string m_messageBody;

	ICMPV6(pcap_pkthdr* header, const u_char* pkt_data, unsigned int idx) : IPV6(header, pkt_data, idx) {
		m_ICMPV6type = pkt_data[Packet::pos++];
		m_code = pkt_data[Packet::pos++];
		m_ICMPV6Checksum = Packet::parseShort();
		m_messageLength = IPV6::m_payloadLength - 4;
		m_messageBody = parse(m_messageLength);

		Packet::m_strType = "ICMPV6";
		std::stringstream ss;

		switch (m_ICMPV6type) {
		case 128:
			ss << "Echo (ping) reply ";
			break;
		case 129:
			ss << "Echo (ping) request ";
			break;
		default:
			ss << "Unknown code " << m_ICMPV6type;
			break;
		}

		ss << " len = " << m_messageLength << " hop limit = " << (int)IPV6::m_hopLimit;

		Packet::m_description = ss.str();
	}

	std::string toString() override {
		std::stringstream ss;

		ss << "ICMPV4 packet at " << Packet::m_texts["time"] << " of type " << m_ICMPV6type << " of code " << m_code << " (with checksum " << m_ICMPV6Checksum << ")\n";

		return ss.str();
	}

	json jsonify() override {
		auto j = IPV6::jsonify();

		j["ICMP"] = "start";
		j["Type"] = m_ICMPV6type;
		j["Code"] = m_code;
		j["ICMP Checksum"] = m_ICMPV6Checksum;
		j["length of message"] = m_messageLength;
		j["message"] = m_messageBody;

		return j;
	}

	void render() override {
		Renderer::render(this);
	}
};