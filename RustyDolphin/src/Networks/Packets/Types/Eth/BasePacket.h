#pragma once
#include <WinSock2.h>

struct BasePacket {
	u_char m_phyDst[6];
	u_char m_phySrc[6];
	short m_type;
};