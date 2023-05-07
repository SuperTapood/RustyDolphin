#pragma once

#include "TCPOption.h"

class TCPWScale : public TCPOption {
public:
	unsigned short m_len;
	unsigned short m_shift;

	TCPWScale(pcap_pkthdr* header, const u_char* pkt_data, unsigned int* pos);

	std::string toString() override;
};