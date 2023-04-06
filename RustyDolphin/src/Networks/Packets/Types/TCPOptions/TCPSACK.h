#pragma once

#include "TCPOption.h"

class TCPSACK : public TCPOption {
public:
	int len;
	int edges;
	long long* Redges;
	long long* Ledges;

	TCPSACK(pcap_pkthdr* header, const u_char* pkt_data, int* pos);

	std::string toString() override;
};