#include "Capture.h"

#include <sstream>
#include <tchar.h>
#include <vector>
#include <string>
#include <iostream>
#include "Packets/Packets.h"
#include "../Base/MacroSettings.h"
#include "../Base/Data.h"
#include "../Base/Logger.h"

pcap_if_t* Capture::m_alldevs;
int Capture::m_devs;
std::vector<std::string> Capture::m_devNames;

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

	char errbuf[PCAP_ERRBUF_SIZE];

	std::stringstream ss;

	// get the stupid devices and put them into the stupid variable
	if (pcap_findalldevs(&m_alldevs, errbuf) == -1)
	{
		ss << errbuf;
		Logger::log("Error in pcap_findalldevs: " + ss.str());
		exit(1);
	}

	m_devs = 0;

	for (pcap_if_t* d = m_alldevs; d; d = d->next, m_devs++);

	if (m_devs == 0) {
		Logger::log("No interfaces found! Make sure Npcap is installed.");
		exit(1);
	}

	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		Logger::log("Error initializing Winsock");
		exit(1);
	}
}

void Capture::release() {
	pcap_freealldevs(m_alldevs);
	WSACleanup();
}

pcap_if_t* Capture::getDev(int index) {
	if (index < 0 || index > m_devs) {
		std::stringstream ss;
		ss << index;
		Logger::log("device index " + ss.str() + " does not exist :(");
		exit(1);
	}

	pcap_if_t* d = m_alldevs;
	for (; index > 0; index--, d = d->next);

	return d;
}

std::vector<std::string> Capture::getDeviceNames(bool verbose) {
	if (m_devNames.size() != 0) {
		return m_devNames;
	}
	auto d = m_alldevs;
	for (int i = 0; i < m_devs; i++) {
		std::stringstream ss;
		if (d->description) {
			ss << d->description;
		}
		else {
			ss << "unknown interface";
		}

		if (verbose) {
			ss << "(" << d->name << ")";
		}
		m_devNames.push_back(ss.str());
		d = d->next;
	}

	return m_devNames;
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
		Logger::log("adapter handle is nullptr. " + ss.str());
		exit(1);
	}

	return adhandle;
}

pcap_t* Capture::load(std::string name) {
	char errbuf[PCAP_ERRBUF_SIZE];

	auto handle = pcap_open_offline(name.c_str(), errbuf);

	if (handle == nullptr) {
		Logger::log("Unable to open the file.");
		exit(1);
	}

	return handle;
}

void Capture::capturePackets() {
	auto adapter = Data::chosenAdapter;
	struct pcap_pkthdr* header;
	const u_char* pkt_data;
	int r;

	if (Data::doneLoading) {
		return;
	}

	// find the first good packet pls
	while (pcap_next_ex(adapter, &header, &pkt_data) <= 0);

	auto p = fromRaw(header, pkt_data, Data::capIdx);
	{
		// vector is not thread safe apparently
		// so whenever we interact with an element from it we need to do so with atomics
		std::scoped_lock guard(Data::guard);
		Data::captured.push_back(p);
	}
	
	Data::epochStart = p->m_epoch;
	Data::capIdx++;

	while (true) {
		r = pcap_next_ex(adapter, &header, &pkt_data);
		if (r == 0) {
			continue;
		}

		if (r == -2) {
			// done reading
			Data::doneCapturing = true;
			Data::doneLoading = true;
			return;
		}

		if (Data::doneCapturing) {
			return;
		}

		auto p = fromRaw(header, pkt_data, Data::capIdx);

		{
			std::scoped_lock guard(Data::guard);
			Data::captured.push_back(p);
		}

		Data::capIdx++;
	}
}

void Capture::countPackets(std::vector<int>* counts, int adapterIdx) {
	auto d = getDev(adapterIdx);
	auto adhandle = createAdapter(adapterIdx, true);
	struct pcap_pkthdr* header;
	const u_char* pkt_data;
	int r;

	while ((r = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
		if (Data::doneCounting) {
			break;
		}
		if (r == 0) {
			continue;
		}

		counts->at(adapterIdx) += 1;
	}

	pcap_close(adhandle);
}

void Capture::dumpAll(std::string filename) {
	auto dumpfile = pcap_dump_open(Data::chosenAdapter, filename.c_str());

	for (auto p : Data::captured) {
		pcap_dump((u_char*)dumpfile, p->m_header, p->m_pktData);
	}

	pcap_dump_close(dumpfile);
}