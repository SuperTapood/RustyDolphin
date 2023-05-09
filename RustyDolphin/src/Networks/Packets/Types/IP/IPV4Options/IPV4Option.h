#pragma once

#include <pcap.h>
#include <string>
#include <vector>

class IPV4Option {
public:
	int m_opCode;
	std::string m_name;
	std::string m_value;
	int m_length;

	std::vector<std::string> data;

	IPV4Option(int code, std::string name);
	virtual std::string toString();

protected:
	long long parseLong(unsigned int* start, int end, const u_char* pkt_data);
};
