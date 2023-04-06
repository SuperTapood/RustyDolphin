#include "IPV4Option.h"

#include <sstream>

long long IPV4Option::parseLong(int* start, int end, const u_char* pkt_data) {
	long long out = 0;
	int n = end - (*start);

	for (int i = 0; (*start) < end; (*start)++, i++) {
		out |= (long long)pkt_data[(*start)] << ((n - i - 1) * 8);
	}

	return out;
}

IPV4Option::IPV4Option(int code) {
	optCode = code;
}

std::string IPV4Option::toString() {
	std::stringstream ss;
	ss << "Unknown option of code " << optCode;

	return ss.str();
}