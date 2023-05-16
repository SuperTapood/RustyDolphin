#pragma once
#include <string>
#include <pcap.h>

#include "../../../Eth/Packet.h"

class HopOption {
public:
	unsigned short m_type;
	unsigned short m_length;
	std::string m_data;

	HopOption(Packet* packet);
};