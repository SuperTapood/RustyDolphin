#pragma once

#include "TCPOption.h"

class TCPSACKPerm : public TCPOption {
public:
	unsigned short m_len;

	TCPSACKPerm(pcap_pkthdr* header, const u_char* pkt_data, unsigned int* pos);

	std::string toString() override;
};