#pragma once

#include "../../IP/IP.h"

#include <string>
#include <pcap.h>

template <typename IPVersion>
class IGMP : public IPVersion {
public:
	char m_groupType;
	float m_maxResp;
	int m_checksum;
	std::string m_multicastAddr;

	IGMP(pcap_pkthdr* header, const u_char* pkt_data) : IPVersion(header, pkt_data) {
		m_groupType = pkt_data[Packet::pos++];
		m_maxResp = pkt_data[Packet::pos++] / 10;
		m_checksum = Packet::parseInt();
		m_multicastAddr = Packet::parseIPV4();
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
};