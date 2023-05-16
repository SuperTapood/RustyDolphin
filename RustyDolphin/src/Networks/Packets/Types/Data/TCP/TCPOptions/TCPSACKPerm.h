#pragma once

#include "TCPOption.h"

class Packet;

class TCPSACKPerm : public TCPOption {
public:
	unsigned short m_len;

	TCPSACKPerm(Packet* packet);

	std::string toString() override;
};