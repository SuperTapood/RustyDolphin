#pragma once

#include "IPV6.h"
#include <pcap.h>
#include <uchar.h>

class ICMPV6 : public IPV6 {
public:
	int m_type;
	int m_code;
	long m_ICMPChecksum;
	long m_ICMPChecksum;
	long m_restOfHeader;

	ICMPV6(pcap_pkthdr* header, const u_char* pkt_data);
	std::string toString() override;
	json jsonify() override;
};