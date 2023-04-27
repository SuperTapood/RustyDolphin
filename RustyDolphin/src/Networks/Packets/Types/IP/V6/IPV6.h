#pragma once

#include "../../Eth/Packet.h"

#include <pcap.h>

class IPV6 : public Packet {
public:
	int m_version;
	int m_trafficCls;
	long m_flowLabel;
	long m_payloadLength;
	int m_proto;
	int m_hopLimit;
	std::string m_srcAddr;
	std::string m_destAddr;
	int m_headerLength = 40;

	IPV6(pcap_pkthdr* header, const u_char* pkt_data);
	~IPV6() override = default;

	std::string toString() override;
	json jsonify() override;
};