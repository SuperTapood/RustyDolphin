#pragma once

#include "IPV4.h"

class UDPV4 : public IPV4 {
public:
	int srcPort;
	int destPort;
	int length;
	int checksum;

	UDPV4(pcap_pkthdr* header, const u_char* pkt_data);
	std::string toString() override;
};