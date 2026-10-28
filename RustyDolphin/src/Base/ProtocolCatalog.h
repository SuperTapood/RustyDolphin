#pragma once

#include "../Networks/Packets/Types/Eth/Packet.h"
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <set>
#include <atomic>
#include <memory>
#include "GeoLocation.h"
#include "../Networks/PcapHandle.h"

// Immutable protocol/display catalog. Mutable application state lives in ApplicationState.
class ProtocolCatalog {
public:
	static std::array<const char*, 30>       quotes;
	static std::map<int, std::string> dscpMap;
	static std::map<int, std::string> ecnMap;
	static std::map<int, std::string> hopMap;
	static std::map<unsigned char, std::string> icmpv6Types;
	static std::array<const char*, 10> TCPFlags;
	static std::array<std::string, 26> arpCodes;
	static std::array<std::string, 39> arpHard;
	static std::array<std::string, 44> icmpTypes;

	static void init();
	static std::pair<double, double> mercatorProjection(double longitude, double latitude);
};
