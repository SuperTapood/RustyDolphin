#pragma once
#include <pcap.h>


class IPV6Option {
public:
	unsigned short m_nextHeader;
	unsigned short m_length;

	const u_char* m_pktData;

	IPV6Option(const u_char* pkt_data, unsigned int* pos);
};