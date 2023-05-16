#pragma once

#include "TCPOption.h"

class Packet;

class TCPSACK : public TCPOption {
public:
	int m_len;
	int m_edges;
	unsigned int* m_Redges;
	unsigned int* m_Ledges;

	TCPSACK(Packet* packet);

	std::string toString() override;
};