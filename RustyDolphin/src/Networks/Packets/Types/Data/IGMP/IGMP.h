#pragma once

#include "../../IP/IP.h"
#include "../../../../../GUI/Renderer.h"

#include <string>
#include <pcap.h>


constexpr auto report = 0x16;
constexpr auto leave = 0x17;
constexpr auto query = 0x11;

template <typename IPVersion>
class IGMP : public IPVersion {
public:
	char m_groupType;
	int m_maxResp;
	int m_checksum;
	std::string m_multicastAddr;

	IGMP(pcap_pkthdr* header, const u_char* pkt_data, unsigned int idx) : IPVersion(header, pkt_data, idx) {
		m_groupType = pkt_data[Packet::pos++];
		m_maxResp = pkt_data[Packet::pos++];
		m_checksum = Packet::parseShort();
		m_multicastAddr = Packet::parseIPV4();

		Packet::m_strType = "IGMP (" + Packet::m_strType + ")";

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
			break;
		default:
			ss << "IGMP Packet";
			break;
		}

		Packet::m_description = ss.str();

		Packet::m_expands.insert({ "IGMP Title", false });
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

	std::map<std::string, std::string> getTexts() override {
		if (Packet::m_texts.empty()) {
			IPVersion::getTexts();

			std::stringstream ss;
			switch (m_groupType) {
			case (report):
				Packet::m_texts["groupType"] = "Membership Report";
				break;
			case (leave):
				Packet::m_texts["groupType"] = "Leave Group";
				break;
			case (query):
				Packet::m_texts["groupType"] = "Membership Query";
				break;
			default:
				Packet::m_texts["groupType"] = "Unknown";
				break;
			}

			Packet::m_texts["IGMPType"] = std::format("\tType: {} (0x{:x})", Packet::m_texts["groupType"], m_groupType);

			Packet::m_texts["respTime"] = std::format("\tMax Resp Time: {} sec (0x{:x})", m_maxResp / 10, m_maxResp);

			Packet::m_texts["IGMPChecksum"] = std::format("\tChecksum: 0x{:x}", m_checksum);

			Packet::m_texts["multicastAddr"] = std::format("\tMulticast Address: {}", m_multicastAddr);

		}

		return Packet::m_texts;
	}
};