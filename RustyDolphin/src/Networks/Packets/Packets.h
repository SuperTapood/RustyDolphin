#pragma once

#include "Types/Types.h"

// think of this function as the sorting hat for packets
PKT fromRaw(pcap_pkthdr* header, const u_char* pkt_data, unsigned int idx);