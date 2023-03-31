#pragma once

#include "../Base/Base.h"

#include <pcap.h>
#include <string>
#include <vector>

class Capture {
private:
	static pcap_if_t* alldevs;
	static int len;
	static std::vector<std::string>* names;

	static bool LoadNpcapDlls();
	static void freeDevs();
public:
	// club pinguin is kil
	// no
	Capture() = delete;
	static void init();
	static void free();
	static pcap_if_t* getDev(int index);
	static std::vector<std::string>* getDeviceNames();
	static pcap_t* createAdapter(int devIndex, bool promiscuous = false);
	static void loop(int devIndex, void (*func)(int, pcap_pkthdr*, const u_char*), bool promiscuous);
};