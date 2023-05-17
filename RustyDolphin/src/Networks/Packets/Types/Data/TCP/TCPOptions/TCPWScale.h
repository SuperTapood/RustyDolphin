#pragma once

#include "TCPOption.h"

class Packet;

class TCPWScale : public TCPOption {
public:
	unsigned short m_len;
	unsigned short m_shift;

	TCPWScale(Packet* packet);

	const std::string toString() override;
};