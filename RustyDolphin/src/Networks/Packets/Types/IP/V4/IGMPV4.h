#pragma once

#include "IPV4.h"

#include <string>
#include <pcap.h>

class IGMPV4 : public IPV4 {
public:
	int groupType;
	float maxResp;
	int checksum;
	std::string multicastAddr;

	IGMPV4(pcap_pkthdr* header, const u_char* pkt_data);

	std::string toString() override;
	json jsonify() override;
};