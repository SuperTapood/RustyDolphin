#pragma once

#include "TCPOption.h"

class TCPNOP : public TCPOption {
public:
	TCPNOP();

	const std::string toString() override;
};