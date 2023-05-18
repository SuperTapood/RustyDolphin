#pragma once

#include "IPV4Option.h"
#include "../../Eth/Packet.h"

#include <string>

class Packet;

class RouterAlert : public IPV4Option {
public:
	bool m_copyOnFrag;
	int m_clsType;
	int m_code;
	short m_extra;

	RouterAlert(Packet* packet);

	std::string toString() override;
};