#pragma once

#include <pcap.h>

BOOL LoadNpcapDlls();

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);