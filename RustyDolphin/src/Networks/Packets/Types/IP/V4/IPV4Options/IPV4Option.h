#pragma once

#include <pcap.h>
#include <string>

class IPV4Option {
public:
	int m_opCode;

	IPV4Option(int code);
	virtual std::string toString();

protected:
	long long parseLong(unsigned int* start, int end, const u_char* pkt_data);
};
