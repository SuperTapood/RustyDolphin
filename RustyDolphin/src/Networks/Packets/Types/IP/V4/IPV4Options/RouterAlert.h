#pragma once

#include "IPV4Option.h"

#include <string>

class RouterAlert : public IPV4Option {
public:
	bool m_copyOnFrag;
	int m_clsType;
	int m_code;
	int m_length;
	long m_extra;

	RouterAlert(pcap_pkthdr* header, const u_char* pkt_data, int* pos);

	std::string toString() override;
};