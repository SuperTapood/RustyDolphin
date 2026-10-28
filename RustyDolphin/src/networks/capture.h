#pragma once

#include <pcap.h>
#include <string>
#include <vector>
#include <atomic>
#include "PcapHandle.h"
struct ApplicationState;

class Capture {
public:
	// everyone remembers where they were when they got the news
	Capture() = delete;
	static void init();
	static void release();
	static pcap_if_t* getDev(int index);
	static std::vector<std::string> getDeviceNames(bool verbose = false);
	static PcapHandle createAdapter(int devIndex, bool promiscuous = false);
	static void capturePackets(ApplicationState& state);
	static PcapHandle load(ApplicationState& state, std::string name);
	static void countPackets(ApplicationState& state, std::vector<std::atomic_int>& counts, int adapterIdx);
	static void dumpAll(ApplicationState& state, std::string filename);

private:
	static pcap_if_t* m_alldevs;
	static int m_devs;
	static std::vector<std::string> m_devNames;

	static bool LoadNpcapDlls();
};
