#include "TCPOption.h"

TCPOption::TCPOption(int code) {
	this->m_code = code;
}

std::string TCPOption::toString() {
	std::stringstream ss;

	ss << "Anonymous Option of code " << m_code;

	return ss.str();
}

long long TCPOption::parseLong(int* start, int end, const u_char* pkt_data) {
	long long out = 0;
	int n = end - (*start);

	for (int i = 0; (*start) < end; (*start)++, i++) {
		out |= (long long)pkt_data[(*start)] << ((n - i - 1) * 8);
	}

	return out;
}