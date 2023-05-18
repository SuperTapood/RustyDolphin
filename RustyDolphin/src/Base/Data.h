#pragma once

#include "../Networks/Packets/Types/Eth/Packet.h"
#include <vector>
#include <string>
#include <thread>
#include <mutex>

class Data {
public:
	static std::vector<Packet*>              captured;
	static int                               selected;
	static bool                              doneCounting;
	static std::array<const char*, 30>       quotes;
	static long double                       epochStart;
	static std::map<int, std::string> dscpMap;
	static std::map<int, std::string> ecnMap;
	static std::map<int, std::string> hopMap;
	static std::map<unsigned char, std::string> icmpv6Types;
	static bool doneCapturing;
	static long capIdx;
	static bool showStop;
	static bool showStart;
	static std::thread captureThread;
	static pcap_t* chosenAdapter;
	static int selectExpand;
	static std::mutex guard;
	static bool fileAdapter;
	static std::array<const char*, 10> TCPFlags;
	static bool doneLoading;
	static bool showSave;
	static bool showLoad;

	static void addPacket(Packet* p);
	static void init();
};