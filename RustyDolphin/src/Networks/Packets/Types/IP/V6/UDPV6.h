#pragma once

#include "IPV6.h"

class UDPV6 : public IPV6 {
public:
	int m_srcPort;
	int m_destPort;
	int m_length;
	int m_UDPChecksum;

	UDPV6(pcap_pkthdr* header, const u_char* pkt_data);
	std::string toString() override;
	json jsonify() override;
};