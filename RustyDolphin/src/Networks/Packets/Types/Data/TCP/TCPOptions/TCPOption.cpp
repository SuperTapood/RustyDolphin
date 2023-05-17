#include "TCPOption.h"

TCPOption::TCPOption(int code) {
	this->m_kind = code;
}

const std::string TCPOption::toString() {
	std::stringstream ss;

	ss << "Anonymous Option of code " << m_kind;

	return ss.str();
}