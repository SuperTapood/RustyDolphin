#pragma once

#include "../Eth/Packet.h"

#include <pcap.h>

class IPV6 : public Packet {
public:
	unsigned char m_version = 6;
	unsigned short m_trafficCls;
	unsigned long m_flowLabel;
	unsigned int m_payloadLength;
	unsigned char m_nextHeader;
	unsigned char m_hopLimit;
	std::string m_srcAddr;
	std::string m_destAddr;
	int m_headerLength = 40;

	IPV6(pcap_pkthdr* header, const u_char* pkt_data, unsigned int idx);
	~IPV6() override = default;

	std::string toString() override;
	json jsonify() override;
	virtual void render() override;
};