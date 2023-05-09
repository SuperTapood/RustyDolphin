#pragma once

#include "../Networks/Packets/Types/Types.h"
#include <vector>
#include <string>

class Data {
public:
	static std::vector<Packet*>              captured;
	static int                               selected;
	static bool                              doneCounting;
	static std::array<const char*, 30>       quotes;
	static long double                       epochStart;
	static std::map<int, std::string> dscpMap;
	static std::map<int, std::string> ecnMap;

	static void addPacket(Packet* p);
	static void init();
};