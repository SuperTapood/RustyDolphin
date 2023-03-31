#include "Structs.h"

ip_address* LONG2ADDR(DWORD addr) {
	ip_address* out = new ip_address();

	out->byte1 = (addr & 0xFF000000) >> 24;
	out->byte2 = (addr & 0x00FF0000) >> 16;
	out->byte3 = (addr & 0x0000FF00) >> 8;
	out->byte4 = (addr & 0x000000FF);

	return out;
}

std::string ADDR2STR(const ip_address* addr) {
	std::stringstream os;
	os << (int)addr->byte4 << "." << (int)addr->byte3 << "." << (int)addr->byte2 << "." << (int)addr->byte1;
	return os.str();
}

std::string ADDR2STR(DWORD addr) {
	return ADDR2STR(LONG2ADDR(addr));
}