#pragma once

#include "../Networks/Packets/Types/Types.h"
#include <vector>


class Data {
public:
	static std::vector<Packet*> captured;
	static int                  selected;

	static void addPacket(Packet* p);
};