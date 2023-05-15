#pragma once

#include "../Base/Base.h"

#include <pcap.h>
#include <string>
#include <vector>

class Capture {
public:
	// club pinguin is kil
	// no
	Capture() = delete;
	static void init();
	static void release();
	static pcap_if_t* getDev(int index);
	static std::vector<std::string> getDeviceNames(bool verbose = false);
	static pcap_t* createAdapter(int devIndex, bool promiscuous = false);
	static void capturePackets();
	static void dump(struct pcap_pkthdr* h, const u_char* pkt);
	static pcap_t* load(std::string name);
	static void countPackets(std::vector<int>* counts, int adapterIdx);

private:
	static pcap_if_t* m_alldevs;
	static int m_devs;
	static std::vector<std::string> m_devNames;
	static pcap_dumper_t* m_dumpfile;

	static bool LoadNpcapDlls();
};