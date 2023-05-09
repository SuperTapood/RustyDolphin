#pragma once

#include "../../IP/IP.h"
#include "../../../../../GUI/Renderer.h"

#include <string>
#include <pcap.h>

template <typename IPVersion>
class IGMP : public IPVersion {
public:
	char m_groupType;
	float m_maxResp;
	int m_checksum;
	std::string m_multicastAddr;

	IGMP(pcap_pkthdr* header, const u_char* pkt_data, unsigned int idx) : IPVersion(header, pkt_data, idx) {
		m_groupType = pkt_data[Packet::pos++];
		m_maxResp = pkt_data[Packet::pos++] / 10;
		m_checksum = Packet::parseShort();
		m_multicastAddr = Packet::parseIPV4();

		Packet::m_strType = "IGMP (" + Packet::m_strType + ")";

		constexpr auto report = 0x16;
		constexpr auto leave = 0x17;
		constexpr auto query = 0x11;

		std::stringstream ss;
		switch (m_groupType) {
		case (report):
			ss << "Membership Report Group " << m_multicastAddr;
			break;
		case (leave):
			ss << "Leave Group " << m_multicastAddr;
			break;
		case (query):
			ss << "Membership Query, general";
		default:
			ss << "IGMP Packet";
		}

		Packet::m_description = ss.str();
	}

	std::string toString() override {
		std::stringstream ss;

		ss << "IGMP of group type " << m_groupType << " max resp time is " << m_maxResp << " for multicast addr: " << m_multicastAddr << "\n";

		return ss.str();
	}

	json jsonify() override {
		auto j = IPVersion::jsonify();

		j["IGMP"] = "start";
		j["Group Type"] = m_groupType;
		j["Max Response Time"] = m_maxResp;
		j["IGMP Checksum"] = m_checksum;
		j["Multicast Address"] = m_multicastAddr;

		return j;
	}

	void render() override {
		Renderer::render(this);
	}
};