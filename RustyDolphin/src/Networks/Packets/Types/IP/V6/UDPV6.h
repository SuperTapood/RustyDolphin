#pragma once

#include "IPV6.h"

class UDPV6 : public IPV6 {
public:
	int srcPort;
	int destPort;
	int length;
	int checksum;

	UDPV6(pcap_pkthdr* header, const u_char* pkt_data);
	std::string toString() override;
};