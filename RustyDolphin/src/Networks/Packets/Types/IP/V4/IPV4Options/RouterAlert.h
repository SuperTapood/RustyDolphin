#pragma once

#include "IPV4Option.h"

#include <string>

class RouterAlert : public IPV4Option {
public:
	bool copyOnFrag;
	int clsType;
	int code;
	int length;
	long extra;

	RouterAlert(pcap_pkthdr* header, const u_char* pkt_data, int* pos);

	std::string toString() override;
};