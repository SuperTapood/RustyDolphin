#pragma once

#include "TCPOption.h"

class TCPSACK : public TCPOption {
public:
	int m_len;
	int m_edges;
	unsigned int* m_Redges;
	unsigned int* m_Ledges;

	TCPSACK(pcap_pkthdr* header, const u_char* pkt_data, unsigned int* pos);

	std::string toString() override;
};