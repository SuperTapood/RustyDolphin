#pragma once

#include "GeoLocation.h"
#include "../Networks/PcapHandle.h"
#include "../Networks/Packets/Types/Eth/Packet.h"

#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

struct ApplicationState {
	std::vector<std::unique_ptr<Packet>> captured;
	int selected = -1;
	std::atomic_bool doneCounting = false;
	long double epochStart = 0;
	std::atomic_bool doneCapturing = false;
	std::atomic_long capIdx = 0;
	bool showStop = false;
	bool showStart = false;
	std::jthread captureThread;
	PcapHandle chosenAdapter;
	std::mutex guard;
	bool fileAdapter = false;
	std::string loadedCapturePath;
	bool doneLoading = false;
	bool showSave = false;
	bool showLoad = false;
	char filterTxt[1024]{};
	bool showBadFilter = false;
	std::string filterIssue;
	std::map<std::string, std::string> filter;
	bool newFilter = true;
	bool showFilterHelp = false;
	long displayed = 0;
	long showGeoTrace = -1;
	std::vector<GeoLocation> locs;
	std::jthread geoLocThread;
	std::mutex geoGuard;
	std::atomic_bool geoDone = false;
	bool geoAlert = false;
	std::string geoError;
	std::atomic_bool geoTerminate = false;
	std::atomic_int geoState = -1;
	std::string hopAddr;

	void addPacket(std::unique_ptr<Packet> packet);
	void clearPackets();
	void processFilter();
};
