#pragma once

#include "../../IP/IP.h"
#include "../../../../../GUI/Renderer.h"

#include <string>
#include <pcap.h>

template <typename IPVersion>
class IGMP : public IPVersion {
public:
	char m_groupType;
	int m_maxResp;
	int m_checksum;
	std::string m_multicastAddr;

	std::string m_igmpTitle;
	std::string m_groupTypeStr;
	std::string m_typeStr;
	std::string m_timeStr;
	std::string m_checkStr;
	std::string m_multiStr;

	IGMP(pcap_pkthdr* header, const u_char* pkt_data, unsigned int idx) : IPVersion(header, pkt_data, idx) {
		m_groupType = pkt_data[Packet::pos++];
		m_maxResp = pkt_data[Packet::pos++];
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
			m_groupTypeStr = "Membership Report";
			break;
		case (leave):
			ss << "Leave Group " << m_multicastAddr;
			m_groupTypeStr = "Leave Group";
			break;
		case (query):
			ss << "Membership Query, general";
			m_groupTypeStr = "Membership Query";
			break;
		default:
			ss << "IGMP Packet";
			m_groupTypeStr = "Unknown";
			break;
		}

		Packet::m_description = ss.str();

		Packet::m_expands.insert({ "IGMP Title", false });

		m_igmpTitle = "Internet Group Management Protocol";

		m_typeStr = std::format("\tType: {} (0x{:x})", m_groupTypeStr, m_groupType);

		m_timeStr = std::format("\tMax Resp Time: {} sec (0x{:x})", m_maxResp / 10, m_maxResp);

		m_checkStr = std::format("\tChecksum: 0x{:x}", m_checksum);

		m_multiStr = std::format("\tMulticast Address: {}", m_multicastAddr);
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

	virtual void renderExpanded() override {
		Renderer::renderExpanded(this);
	}
};