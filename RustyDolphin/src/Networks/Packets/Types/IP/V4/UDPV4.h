#pragma once

#include "IPV4.h"

class UDPV4 : public IPV4 {
public:
	short m_srcPort;
	short m_destPort;
	short m_length;
	short m_UDPChecksum;
	int m_payloadLength;
	std::string m_payload;

	UDPV4(pcap_pkthdr* header, const u_char* pkt_data);
	std::string toString() override;
	json jsonify() override;
};