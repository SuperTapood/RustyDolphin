#pragma once

#include "IPV6.h"

class IGMPV6 : public IPV6 {
public:
	IGMPV6(pcap_pkthdr* header, const u_char* pkt_data);
};