#pragma once

#include "IPV4.h"

#include <string>
#include <pcap.h>

class IGMPV4 : public IPV4 {
public:
	char m_groupType;
	float m_maxResp;
	int m_checksum;
	std::string m_multicastAddr;

	IGMPV4(pcap_pkthdr* header, const u_char* pkt_data);

	std::string toString() override;
	json jsonify() override;
};