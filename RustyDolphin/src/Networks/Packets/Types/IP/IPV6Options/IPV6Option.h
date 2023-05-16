#pragma once
#include <pcap.h>

#include "../../Eth/Packet.h"

class IPV6Option {
public:
	unsigned short m_nextHeader;
	unsigned short m_length;

	IPV6Option(Packet* packet);
};