#pragma once

#include "IPV6.h"
#include <pcap.h>
#include <uchar.h>

class ICMPV6 : public IPV6 {
public:
	int type;
	int code;
	long ICMPChecksum;
	long restOfHeader;

	ICMPV6(pcap_pkthdr* header, const u_char* pkt_data);
	std::string toString() override;
	json jsonify() override;
};