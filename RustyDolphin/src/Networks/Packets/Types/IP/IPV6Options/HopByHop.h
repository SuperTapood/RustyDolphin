#pragma once

#include "IPV6Option.h"
#include "HopOptions/HopOption.h"
#include <vector>

class HopByHop : public IPV6Option {
public:
	std::vector<HopOption> m_options;
	

	HopByHop(const u_char* pkt_data, unsigned int* pos);
};