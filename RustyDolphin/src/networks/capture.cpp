#include "Capture.h"

#include <sstream>
#include <tchar.h>
#include <vector>

pcap_if_t* Capture::alldevs;
int Capture::len;
std::vector<std::string>* Capture::names;

bool Capture::LoadNpcapDlls() {
	_TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		std::stringstream ss;
		ss << GetLastError();
		Logger::log("Error in GetSystemDirectory: " + ss.str());
		return false;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		std::stringstream ss;
		ss << GetLastError();
		Logger::log("Error in SetDllDirectory: " + ss.str());
		return false;
	}
	return true;
}

void Capture::init() {
	// load the stupid dlls
	if (!LoadNpcapDlls()) {
		Logger::log("Couldn't load Npcap");
		exit(1);
	}

	std::stringstream ss;

	char errbuf[PCAP_ERRBUF_SIZE];

	// get the stupid devices and put  them into the stupid variable
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		ss << errbuf;
		Logger::log("Error in pcap_findalldevs: " + ss.str());
		exit(1);
	}

	len = 0;

	for (pcap_if_t* d = alldevs; d; d = d->next, len++);

	if (len == 0) {
		Logger::log("No interfaces found! Make sure Npcap is installed.");
		exit(1);
	}
}

void Capture::free() {
	pcap_freealldevs(alldevs);
}

pcap_if_t* Capture::getDev(int index) {
	if (index < 0 || index > len) {
		std::stringstream ss;
		ss << index;
		Logger::log("device index " + ss.str() + " does not exist :(");
		exit(1);
	}

	pcap_if_t* d = alldevs;
	for (; index > 0; index--, d = d->next);

	return d;
}

std::vector<std::string>* Capture::getDeviceNames() {
	if (names != nullptr) {
		return names;
	}
	names = new std::vector<std::string>;
	auto d = alldevs;
	for (int i = 0; i < len; i++) {
		std::stringstream ss;
		ss << d->name << " ";
		if (d->description) {
			ss << " (" << d->description << ")\n";
		}
		else {
			ss << " (No description available)\n";
		}
		names->push_back(ss.str());
		d = d->next;
	}

	return names;
}

pcap_t* Capture::createAdapter(int devIndex, bool promiscuous) {
	auto dev = getDev(devIndex);
	int prom = 1;
	if (!promiscuous) {
		prom = 0;
	}

	char errbuf[PCAP_ERRBUF_SIZE];

	auto adhandle = pcap_open_live(dev->name, 65536, prom, 20, errbuf);

	if (adhandle == nullptr) {
		std::stringstream ss;
		ss << "Unable to open the adapter. " << dev->name << " is not supported by Npcap";
		Logger::log(ss.str());
		exit(1);
	}

	return adhandle;
}

void Capture::loop(int devIndex, void (*func)(int, pcap_pkthdr*, const u_char*), bool promiscuous = false) {
	auto adhandle = createAdapter(devIndex, promiscuous);
	struct pcap_pkthdr* header;
	const u_char* pkt_data;
	int r;

	while ((r = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
		if (r == 0) {
			continue;
		}
		func(r, header, pkt_data);
	}

	pcap_close(adhandle);
}