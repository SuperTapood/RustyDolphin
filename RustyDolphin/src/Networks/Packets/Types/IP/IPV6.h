#pragma once

#include "../Eth/Packet.h"

#include <pcap.h>

class IPV6 : public Packet {
public:
	char m_version = 6;
	short m_trafficCls;
	long m_flowLabel;
	int m_payloadLength;
	char m_nextHeader;
	char m_hopLimit;
	std::string m_srcAddr;
	std::string m_destAddr;
	int m_headerLength = 40;

	IPV6(pcap_pkthdr* header, const u_char* pkt_data, unsigned int idx);
	~IPV6() override = default;

	std::string toString() override;
	json jsonify() override;
	virtual void render() override;
};