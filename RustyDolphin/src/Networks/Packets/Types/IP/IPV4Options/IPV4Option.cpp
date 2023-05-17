#include "IPV4Option.h"

#include <sstream>

IPV4Option::IPV4Option(int code, std::string name) {
	m_opCode = code;
	m_name = name;
}

std::string IPV4Option::toString() {
	std::stringstream ss;
	ss << "Unknown option of code " << m_opCode;

	return ss.str();
}