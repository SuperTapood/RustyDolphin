#include <iostream>
#include <cstdio>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <Winsock2.h>
#include <Windows.h>
#include "Base/Base.h"
#include "Networks/Networks.h"
#include "Win/Win.h"
#include <cstdint>
#include <thread>
#include <algorithm>

static std::atomic<bool> done(false);

void free() {
	Logger::free();
	Capture::free();
}

void init() {
	atexit(free);
	Logger::init();
	Capture::init();
	SDK::init();
}

void callback(pcap_pkthdr* header, const u_char* pkt_data) {
	auto p = fromRaw(header, pkt_data);

	// p->toString();

	std::cout << p->toString();
}

void sampleCallback(pcap_pkthdr* header, const u_char* pkt_data, std::string file) {
	auto p = fromRaw(header, pkt_data);

	// p->toString();

	std::cout << p->toString();
}

void countPackets(std::vector<int>* counts, int adapterIdx) {
	auto d = Capture::getDev(adapterIdx);
	auto adhandle = Capture::createAdapter(adapterIdx, true);
	struct pcap_pkthdr* header;
	const u_char* pkt_data;
	int r;

	while ((r = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
		if (done) {
			break;
		}
		if (r == 0) {
			continue;
		}

		counts->at(adapterIdx) += 1;
	}

	pcap_close(adhandle);
}

int main()
{
	init();

	std::cout << "hold on. rates are being captured.\n";

	int constexpr seconds = 1;

	auto names = Capture::getDeviceNames();

	auto counts = std::vector<int>(names->size(), 0);

	auto threads = std::vector<std::thread*>();

	for (int i = 0; i < names->size(); i++) {
		threads.push_back(new std::thread(countPackets, &counts, i));
	}

	std::this_thread::sleep_for(std::chrono::seconds(seconds));
	done = true;

	std::for_each(threads.cbegin(), threads.cend(), [](std::thread* t) {t->join(); });

	std::cout << "the following adapters were detected:\n";

	for (int i = 0; i < names->size(); i++) {
		std::cout << i + 1 << ". " << names->at(i) << "(packets rate: " << ((float)counts.at(i) / (float)seconds) << " per second)\n";
	}

	int adapterIdx = 0;

	std::cout << "Enter the number of the adapter you wish to use: ";

	std::cin >> adapterIdx;

	if (adapterIdx <= 0 || adapterIdx > names->size()) {
		std::cout << "\nnah man that's a bad adapter index\nbetter luck next time\n";
		return 0;
	}

	// we need it zero indexed
	adapterIdx -= 1;

	std::cout << "\nDo you want to enable promiscuous mode? (Y/N): ";

	std::string temp;

	std::cin >> temp;

	bool promiscuous = temp == "Y";

	std::cout << "\nHow Many packets do you want to capture: ";

	int maxPackets;

	std::cin >> maxPackets;

	if (maxPackets <= 0) {
		std::cout << "\nno\n";
		return 0;
	}

	Capture::sample(adapterIdx, sampleCallback, promiscuous, maxPackets);

	return 0;
}