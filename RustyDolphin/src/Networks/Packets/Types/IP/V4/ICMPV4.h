#pragma once

#include "IPV4.h"
#include <pcap.h>
#include <uchar.h>

class ICMPV4 : public IPV4 {
public:
	int type;
	int code;
	long ICMPChecksum;
	long restOfHeader;

	ICMPV4(pcap_pkthdr* header, const u_char* pkt_data);
	std::string toString() override;
	json jsonify() override;
};