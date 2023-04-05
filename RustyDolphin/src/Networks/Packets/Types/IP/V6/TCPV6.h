#pragma once

#include "IPV6.h"

class TCPV6 : public IPV6 {
public:
	TCPV6(pcap_pkthdr* header, const u_char* pkt_data);
};