#pragma once

#include "IPV4.h"

class IGMPV4 : public IPV4 {
public:
	IGMPV4(pcap_pkthdr* header, const u_char* pkt_data);
};