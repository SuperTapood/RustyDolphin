#pragma once

#include "../../Eth/Packet.h"
#include "../../IP/IP.h"
#include <pcap.h>
#include <uchar.h>

template <typename IPVersion>
class ICMP : public IPVersion {
public:
	unsigned short m_ICMPtype;
	unsigned short m_code;
	unsigned short m_ICMPChecksum;
	unsigned short m_indentifierBE;
	unsigned short m_indentifierLE;
	unsigned short m_seqNumberBE;
	unsigned short m_seqNumberLE;
	unsigned long long m_ROHLength;
	std::string m_restOfHeader;

	ICMP(pcap_pkthdr* header, const u_char* pkt_data) : IPVersion(header, pkt_data) {
		m_ICMPtype = pkt_data[Packet::pos++];
		m_code = pkt_data[Packet::pos++];
		m_ICMPChecksum = Packet::parseShort();
		m_indentifierLE = Packet::parseShort();
		m_indentifierBE = htons(m_indentifierLE);
		m_seqNumberLE = Packet::parseShort();
		m_seqNumberBE = htons(m_seqNumberLE);
		m_ROHLength = Packet::m_len - Packet::pos;
		m_restOfHeader = Packet::parse(m_ROHLength);
	}

	std::string toString() override {
		std::stringstream ss;

		ss << "ICMPV4 packet at " << IPVersion::m_time << " of type " << m_ICMPtype << " of code " << m_code << " (with checksum " << m_ICMPChecksum << " and rest of header is " << m_restOfHeader << ")\n";

		return ss.str();
	}

	json jsonify() override {
		auto j = IPVersion::jsonify();

		j["ICMPV4"] = "start";
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
};