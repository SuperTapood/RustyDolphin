#pragma once

#include "Types/Types.h"

// think of this function as the sorting hat for packets
// this takes in a packet, figures out its type, and return it masked as a Packet*
PKT fromRaw(pcap_pkthdr* header, const u_char* pkt_data, unsigned int idx);