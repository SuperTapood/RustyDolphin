#pragma once

#include <WinSock2.h>
#include <pcap.h>
#include <string>
#include <sstream>

#include "../../../Eth/Packet.h"

class TCPOption {
public:
	unsigned int m_kind;
	unsigned int m_size;

	TCPOption(int code);

	const virtual std::string toString();
};