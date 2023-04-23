#pragma once

#include <pcap.h>
#include <string>

class IPV4Option {
private:
	int optCode;

protected:
	long long parseLong(int* start, int end, const u_char* pkt_data);

public:
	IPV4Option(int code);

	virtual std::string toString();
};
