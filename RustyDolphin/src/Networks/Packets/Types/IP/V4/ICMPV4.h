#pragma once

#include "IPV4.h"
#include <pcap.h>
#include <uchar.h>

class ICMPV4 : public IPV4 {
public:
	int m_ICMPtype;
	int m_code;
	long m_ICMPChecksum;
	long m_restOfHeader;

	ICMPV4(pcap_pkthdr* header, const u_char* pkt_data);
	std::string toString() override;
	json jsonify() override;
};