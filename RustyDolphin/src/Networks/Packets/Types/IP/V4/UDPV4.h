#pragma once

#include "IPV4.h"

class UDPV4 : public IPV4 {
public:
	int m_srcPort;
	int m_destPort;
	int m_length;
	int m_UDPChecksum;

	UDPV4(pcap_pkthdr* header, const u_char* pkt_data);
	std::string toString() override;
	json jsonify() override;
};