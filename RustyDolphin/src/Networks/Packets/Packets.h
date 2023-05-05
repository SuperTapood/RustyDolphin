#pragma once

#include "Types/Types.h"

PKT fromRaw(pcap_pkthdr* header, const u_char* pkt_data, unsigned int idx);