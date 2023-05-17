#pragma once

#include "TCPOption.h"

class Packet;

class TCPMSS : public TCPOption {
public:
	unsigned short m_len;
	unsigned short m_value;

	TCPMSS(Packet* packet);

	const std::string toString() override;
};