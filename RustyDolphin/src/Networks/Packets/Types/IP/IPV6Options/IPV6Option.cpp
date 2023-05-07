#include "IPV6Option.h"


IPV6Option::IPV6Option(const u_char* pkt_data, unsigned int* pos) {
	m_nextHeader = pkt_data[(*pos)++];
	m_length = pkt_data[(*pos)++];
	m_pktData = pkt_data;
}