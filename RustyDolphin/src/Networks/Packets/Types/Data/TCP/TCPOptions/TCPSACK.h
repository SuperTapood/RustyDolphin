#pragma once

#include "TCPOption.h"

class Packet;

class TCPSACK : public TCPOption {
public:
	int m_len;
	unsigned int* m_REdges;
	unsigned int* m_LEdges;
	int m_edges;

	TCPSACK(Packet* packet);

	const std::string toString() override;
};