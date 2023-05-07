#pragma once

#include <WinSock2.h>
#include <pcap.h>
#include <string>
#include <sstream>

#include "../../../Eth/Packet.h"

class TCPOption {
protected:
	long long parseLong(unsigned int* start, int end, const u_char* pkt_data);
public:
	unsigned int m_kind;

	TCPOption(int code);

	virtual std::string toString();
};