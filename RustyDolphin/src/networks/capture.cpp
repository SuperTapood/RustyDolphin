#include "Capture.h"

#include <sstream>
#include <tchar.h>
#include <vector>
#include <string>
#include "../Win/SDK.h"
#include <iostream>
#include "Packets/Packets.h"

pcap_if_t* Capture::m_alldevs;
int Capture::m_devs;
std::vector<std::string> Capture::m_devNames;
pcap_dumper_t* Capture::m_dumpfile;

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

	// get the stupid devices and put  them into the stupid variable
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
	if (m_dumpfile != NULL) {
		pcap_dump_close(m_dumpfile);
	}
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

void Capture::dump(struct pcap_pkthdr* h, const u_char* pkt) {
	pcap_dump((u_char*)m_dumpfile, h, pkt);
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

#ifdef _DEBUG
	auto d = Capture::getDev(3);
	auto filter = "";
	struct bpf_program fcode;

	int netmask;
	if (d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without an address
		 * we suppose to be in a C class network */
		netmask = 0xffffff;

	//compile the filter
	if (pcap_compile(adapter, &fcode, filter, 1, netmask) < 0)
	{
		fprintf(stderr,
			"\nUnable to compile the packet filter. Check the syntax.\n");
		exit(-1);
	}

	//set the filter
	if (pcap_setfilter(adapter, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		exit(-1);
	}
#endif

	auto idx = 0;

	while (pcap_next_ex(adapter, &header, &pkt_data) <= 0) {}

	Data::epochStart = (double)header->ts.tv_sec + (double)header->ts.tv_usec / 1000000.0;

	auto p = fromRaw(header, pkt_data, idx++);
	{
		std::lock_guard<std::mutex> guard(Data::guard);
		Data::captured.push_back(p);
		Data::capturedLength++;
	}

	std::cout << idx << " - " << "\n";

	while ((r = pcap_next_ex(adapter, &header, &pkt_data)) >= 0 && !Data::doneCapturing) {
		if (r == 0) {
			continue;
		}

		auto p = fromRaw(header, pkt_data, idx++);
		{
			std::lock_guard<std::mutex> guard(Data::guard);
			Data::captured.push_back(p);
			Data::capturedLength++;
		}

		//std::cout << idx << " - " << "\n";
	}
}