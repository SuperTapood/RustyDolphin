#pragma once

#include "IPV6.h"

#include <string>

class IGMPV6 : public IPV6 {
public:
	int groupType;
	float maxResp;
	int checksum;
	std::string multicastAddr;

	IGMPV6(pcap_pkthdr* header, const u_char* pkt_data);

	std::string toString() override;
};