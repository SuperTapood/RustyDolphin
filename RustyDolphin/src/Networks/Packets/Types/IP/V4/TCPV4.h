#pragma once

#include "IPV4.h"

class TCPV4 : public IPV4 {
public:
	TCPV4(pcap_pkthdr* header, const u_char* pkt_data);
};