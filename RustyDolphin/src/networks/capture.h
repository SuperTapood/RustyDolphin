#pragma once

#include <pcap.h>
#include <string>
#include <vector>

class Capture {
public:
	// everyone remembers where they were when they got the news
	Capture() = delete;
	static void init();
	static void release();
	static pcap_if_t* getDev(int index);
	static std::vector<std::string> getDeviceNames(bool verbose = false);
	static pcap_t* createAdapter(int devIndex, bool promiscuous = false);
	static void capturePackets();
	static pcap_t* load(std::string name);
	static void countPackets(std::vector<int>* counts, int adapterIdx);
	static void dumpAll(std::string filename);

private:
	static pcap_if_t* m_alldevs;
	static int m_devs;
	static std::vector<std::string> m_devNames;

	static bool LoadNpcapDlls();
};