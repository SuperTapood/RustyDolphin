#pragma once

#include "TCPOption.h"

class TCPMSS : public TCPOption {
public:
	unsigned short m_len;
	unsigned short m_value;

	TCPMSS(pcap_pkthdr* header, const u_char* pkt_data, unsigned int* pos);

	std::string toString() override;
};