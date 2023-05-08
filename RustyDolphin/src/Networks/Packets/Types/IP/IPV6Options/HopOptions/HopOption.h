#pragma once
#include <string>
#include <pcap.h>

class HopOption {
public:
	unsigned short m_type;
	unsigned short m_length;
	std::string m_data;

	HopOption(const u_char* pkt_data, unsigned int* pos);
};