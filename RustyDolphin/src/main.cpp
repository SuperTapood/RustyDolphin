#include <pcap.h>

#include <iostream>
#include <WinSock2.h>
#include <tchar.h>
#include <array>
#include <vector>
#include <format>
#include <iostream>
#include <string>
#include <string_view>
#include <windows.h>
#include <iphlpapi.h>
#include <iostream>
#include <iomanip>

#include "networks/networks.h"
#include "win/win.h"
#include "base/base.h"

void printTables() {
	auto pTcpTable = getTcpTable();

	// Print the TCP table
	std::cout << "Num Entries: " << pTcpTable->dwNumEntries << std::endl;
	for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
		auto& row = pTcpTable->table[i];
		std::cout << "Local Addr: " << ADDR2STR(row.dwLocalAddr) << ", Local Port: " << ntohs((u_short)row.dwLocalPort) << std::endl;
		std::cout << "Remote Addr: " << ADDR2STR(row.dwRemoteAddr) << ", Remote Port: " << ntohs((u_short)row.dwRemotePort) << std::endl;
		std::cout << "pid: " << row.dwOwningPid << " name: " << getNameFromPID(row.dwOwningPid) << std::endl;
	}

	// Free memory
	free(pTcpTable);

	auto pUdpTable = getUdpTable();

	// Print the UDP table
	std::cout << "Num Entries: " << pUdpTable->dwNumEntries << std::endl;
	for (DWORD i = 0; i < pUdpTable->dwNumEntries; i++) {
		auto& row = pUdpTable->table[i];
		
		std::cout << "Local Addr: " << ADDR2STR(row.dwLocalAddr) << ", Local Port: " << ntohs((u_short)row.dwLocalPort) << std::endl;
	}

	// Free memory
	free(pUdpTable);
}

void init() {
	initPIDCache();
}

int main()
{
	init();
	printTables();
	return 0;
	/*std::string res = exec("netstat -aon");
	size_t pos = 0;
	std::string token;
	int index = 0;
	std::string delimiter = "\n";
	std::vector<std::vector<std::string>> data;

	while ((pos = res.find(delimiter)) != std::string::npos) {
		token = res.substr(0, pos);
		res.erase(0, pos + delimiter.length());
		if (index++ < 4) {
			continue;
		}
		std::string temp = "";
		std::vector<std::string> t;
		for (char c : token) {
			if (c != ' ') {
				temp += c;
			}
			else {
				if (temp == "") {
					continue;
				}
				t.push_back(temp);
				temp = "";
			}
		}

		t.push_back(temp);

		data.push_back(t);
	}

	for (std::vector<std::string>& arr : data) {
		std::string pid = arr.at(arr.size() - 1);
		arr.push_back(getNameFromPID(std::stoul(pid)));
	}

	for (std::vector<std::string> arr : data) {
		std::cout << "connection: ";
		for (std::string s : arr) {
			std::cout << s << ", ";
		}
		std::cout << std::endl;
	}

	return 0;*/

	pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fcode;

#ifdef _WIN32
	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}
#endif

	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	// Print the list
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure Npcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum);

	std::cout << inum << std::endl;

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* Open the device */
	/* Open the adapter */
	if ((adhandle = pcap_open_live(d->name,	// name of the device
		65536,			// portion of the packet to capture.
		// 65536 grants that the whole packet will be captured on all the MACs.
		1,				// promiscuous mode (nonzero means promiscuous)
		1000,			// read timeout
		errbuf			// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("listening on %s...\n", d->description);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);
	int netmask;
	if (d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without an address
		 * we suppose to be in a C class network */
		netmask = 0xffffff;

	//compile the filter
	if (pcap_compile(adhandle, &fcode, "udp", 1, netmask) < 0)
	{
		fprintf(stderr,
			"\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//set the filter
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	struct tm* ltime;
	char timestr[16];
	struct pcap_pkthdr* header;
	const u_char* pkt_data;
	time_t local_tv_sec;
	int r;
	struct tm timeinfo;


	bool first = true;

	/* start the capture */
	while ((r = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
		if (r == 0)
			/* Timeout elapsed */
			continue;

		std::cout << r << std::endl;

		/* convert the timestamp to readable format */
		local_tv_sec = header->ts.tv_sec;
		localtime_s(&timeinfo, &local_tv_sec);
		strftime(timestr, sizeof(timestr), "%H:%M:%S", &timeinfo);

		printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
	}

	pcap_close(adhandle);

	return 0;
}