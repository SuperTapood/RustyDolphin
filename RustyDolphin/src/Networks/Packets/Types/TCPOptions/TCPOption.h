#pragma once

#include <WinSock2.h>
#include <pcap.h>
#include <string>
#include <sstream>

class TCPOption {
protected:
	long long parseLong(unsigned int* start, int end, const u_char* pkt_data);
public:
	int m_code;

	TCPOption(int code);

	virtual std::string toString();
};