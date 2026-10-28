#include "Capture.h"

#include <sstream>
#include <tchar.h>
#include <vector>
#include <string>
#include <iostream>
#include <atomic>
#include "Packets/Packets.h"
#include "../Base/MacroSettings.h"
#include "../Base/ProtocolCatalog.h"
#include "../Base/ApplicationState.h"
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
	if (index < 0 || index >= m_devs) {
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

PcapHandle Capture::createAdapter(int devIndex, bool promiscuous) {
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

	return PcapHandle(adhandle);
}

PcapHandle Capture::load(ApplicationState& state, std::string name) {
	char errbuf[PCAP_ERRBUF_SIZE];

	auto handle = pcap_open_offline(name.c_str(), errbuf);

	if (handle == nullptr) {
		Logger::log(std::string("Unable to open capture file: ") + errbuf);
		return {};
	}

	state.loadedCapturePath = std::move(name);
	return PcapHandle(handle);
}

void Capture::capturePackets(ApplicationState& state) {
	auto* adapter = state.chosenAdapter.get();
	struct pcap_pkthdr* header;
	const u_char* pkt_data;
	int r;

	if (state.doneLoading) {
		return;
	}

	std::unique_ptr<Packet> p;
	while (p == nullptr) {
		// Live captures may time out, while offline captures report EOF. Do not
		// spin forever when a capture is empty, invalid, or is asked to stop.
		r = pcap_next_ex(adapter, &header, &pkt_data);
		if (r == 0) {
			if (state.doneCapturing) return;
			continue;
		}
		if (r < 0 || state.doneCapturing) {
			state.doneCapturing = true;
			if (r == -2) state.doneLoading = true;
			return;
		}
		try {
			p.reset(fromRaw(header, pkt_data, static_cast<unsigned int>(state.capIdx.load())));
		}
		catch (const std::exception& error) {
			Logger::log(std::string("Skipping malformed packet: ") + error.what());
		}
	}
	state.epochStart = p->m_epoch;
	state.addPacket(std::move(p));
	while (true) {
		r = pcap_next_ex(adapter, &header, &pkt_data);
		if (r == 0) {
			continue;
		}

		if (r == -2) {
			// done reading
			state.doneCapturing = true;
			state.doneLoading = true;
			return;
		}

		if (state.doneCapturing) {
			return;
		}

		std::unique_ptr<Packet> nextPacket;
		try {
			nextPacket.reset(fromRaw(header, pkt_data, static_cast<unsigned int>(state.capIdx.load())));
		}
		catch (const std::exception& error) {
			Logger::log(std::string("Skipping malformed packet: ") + error.what());
			continue;
		}

		state.addPacket(std::move(nextPacket));
	}
}

void Capture::countPackets(ApplicationState& state, std::vector<std::atomic_int>& counts, int adapterIdx) {
	auto adhandle = createAdapter(adapterIdx, true);
	struct pcap_pkthdr* header;
	const u_char* pkt_data;
	int r;

	while ((r = pcap_next_ex(adhandle.get(), &header, &pkt_data)) >= 0) {
		if (state.doneCounting) {
			break;
		}
		if (r == 0) {
			continue;
		}

		counts.at(adapterIdx).fetch_add(1, std::memory_order_relaxed);
	}

}

void Capture::dumpAll(ApplicationState& state, std::string filename) {
	auto dumpfile = pcap_dump_open(state.chosenAdapter.get(), filename.c_str());
	if (dumpfile == nullptr) {
		Logger::log("Unable to save capture to " + filename);
		return;
	}

	std::scoped_lock guard(state.guard);
	for (const auto& p : state.captured) {
		pcap_dump((u_char*)dumpfile, p->m_header, p->m_pktData);
	}

	pcap_dump_close(dumpfile);
}
