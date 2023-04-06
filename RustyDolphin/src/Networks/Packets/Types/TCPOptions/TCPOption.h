#pragma once

#include <WinSock2.h>
#include <pcap.h>
#include <string>
#include <sstream>

class TCPOption {
protected:
	long long parseLong(int* start, int end, const u_char* pkt_data);
public:
	int code;

	TCPOption(int code);

	virtual std::string toString();
};