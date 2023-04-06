#pragma once

#include "TCPOption.h"

class TCPNOP : public TCPOption {
public:
	TCPNOP();

	std::string toString() override;
};