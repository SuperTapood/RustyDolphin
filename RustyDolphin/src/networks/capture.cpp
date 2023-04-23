#include "Capture.h"

#include <sstream>
#include <tchar.h>
#include <vector>
#include <string>

pcap_if_t* Capture::alldevs;
int Capture::len;
std::vector<std::string>* Capture::names;
pcap_dumper_t* Capture::dumpfile;

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

std::vector<std::string>* Capture::getDeviceNames(bool verbose) {
	if (names != nullptr) {
		return names;
	}
	names = new std::vector<std::string>;
	auto d = alldevs;
	for (int i = 0; i < len; i++) {
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
		Logger::log("adapter handle is nullptr. ");
		exit(1);
	}

	return adhandle;
}

void Capture::loop(int devIndex, void (*func)(pcap_pkthdr*, const u_char*), bool promiscuous = false) {
	auto d = getDev(devIndex);
	auto adhandle = createAdapter(devIndex, promiscuous);
	struct pcap_pkthdr* header;
	const u_char* pkt_data;
	int r;

	std::stringstream ss;

	ss << "captures/" << time(nullptr) << "-output.pcap";

	dumpfile = pcap_dump_open(adhandle, ss.str().c_str());

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
	if (pcap_compile(adhandle, &fcode, "igmp", 1, netmask) < 0)
	{
		fprintf(stderr,
			"\nUnable to compile the packet filter. Check the syntax.\n");
		exit(-1);
	}

	//set the filter
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		exit(-1);
	}

	while ((r = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
		if (r == 0) {
			continue;
		}
		func(header, pkt_data);
	}

	pcap_close(adhandle);
}

void Capture::sample(int devIndex, void (*func)(pcap_pkthdr*, const u_char*, std::string), bool promiscuous, int maxPackets) {
	auto d = getDev(devIndex);
	auto adhandle = createAdapter(devIndex, promiscuous);
	struct pcap_pkthdr* header;
	const u_char* pkt_data;
	int r;

	std::stringstream ss;

	ss << "captures/" << time(nullptr) << "-output.pcap";

	dumpfile = pcap_dump_open(adhandle, ss.str().c_str());

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
	if (pcap_compile(adhandle, &fcode, "igmp", 1, netmask) < 0)
	{
		fprintf(stderr,
			"\nUnable to compile the packet filter. Check the syntax.\n");
		exit(-1);
	}

	//set the filter
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		exit(-1);
	}

	while ((r = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
		if (r == 0) {
			continue;
		}
		maxPackets--;
		pcap_dump((u_char*)dumpfile, header, pkt_data);

		func(header, pkt_data, ss.str());
	}

	pcap_close(adhandle);
}

void Capture::dump(struct pcap_pkthdr* h, const u_char* pkt) {
	// pcap_dump((u_char*)dumpfile, h, pkt);
}