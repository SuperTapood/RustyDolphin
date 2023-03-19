#include <pcap.h>

#include "init.h"
#include <iostream>

#include <cstdint>
#include <WinSock2.h>

#include <pcap.h>
#include <Winsock2.h>
#include <tchar.h>
#include <array>
#include <vector>
#include <format>
#include <iostream>
#include <string>
#include <string_view>


std::string exec(const char* cmd) {
	std::array<char, 128> buffer{};
	std::string result;
	std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(cmd, "rt"), _pclose);
	if (!pipe) {
		throw std::runtime_error("popen() failed!");
	}

	while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
		result += buffer.data();
	}
	return result;
}


/* 4 bytes IP address */
using ip_address = struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
};

/* IPv4 header */
using ip_header = struct ip_header {
	u_char  ver_ihl; // Version (4 bits) + IP header length (4 bits)
	u_char  tos;     // Type of service 
	u_short tlen;    // Total length 
	u_short identification; // Identification
	u_short flags_fo; // Flags (3 bits) + Fragment offset (13 bits)
	u_char  ttl;      // Time to live
	u_char  proto;    // Protocol
	u_short crc;      // Header checksum
	ip_address  saddr; // Source address
	ip_address  daddr; // Destination address
	u_int  op_pad;     // Option + Padding
};

/* UDP header*/
using udp_header = struct udp_header {
	u_short sport; // Source port
	u_short dport; // Destination port
	u_short len;   // Datagram length
	u_short crc;   // Checksum
};
bool first = true;

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	struct tm ltime;
	char timestr[16];
	ip_header* ih;
	udp_header* uh;
	u_int ip_len;
	u_short sport, dport;
	time_t local_tv_sec;

	/*
	 * unused parameters
	 */
	/*(VOID)(param);
	(VOID)(pkt_data);*/

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	struct tm timeinfo;
	char buffer[80];

	localtime_s(&timeinfo, &local_tv_sec);
	strftime(buffer, sizeof(buffer), "%H:%M:%S", &timeinfo);

	if (first) {
		/* retireve the position of the ip header */
		ih = (ip_header*)(pkt_data +
			14); //length of ethernet header

		/* retireve the position of the udp header */
		ip_len = (ih->ver_ihl & 0xf) * 4;
		uh = (udp_header*)((u_char*)ih + ip_len);

		/* convert from network byte order to host byte order */
		sport = ntohs(uh->sport);
		dport = ntohs(uh->dport);

		/* print ip addresses and udp ports */
		printf("%d.%d.%d.%d.%d -> %d.%d.%d.%d.%d\n",
			ih->saddr.byte1,
			ih->saddr.byte2,
			ih->saddr.byte3,
			ih->saddr.byte4,
			sport,
			ih->daddr.byte1,
			ih->daddr.byte2,
			ih->daddr.byte3,
			ih->daddr.byte4,
			dport);

		printf("%s,%.6d len:%d\n", buffer, header->ts.tv_usec, header->len);
		first = false;
		printf("param - %s\n", param);
		printf("data - %s\n", pkt_data);
	}
}

int main()
{
//	pcap_if_t* alldevs;
//	pcap_if_t* d;
//	int inum;
//	int i = 0;
//	pcap_t* adhandle;
//	char errbuf[PCAP_ERRBUF_SIZE];
//	struct bpf_program fcode;
//
//#ifdef _WIN32
//	/* Load Npcap and its functions. */
//	if (!LoadNpcapDlls())
//	{
//		fprintf(stderr, "Couldn't load Npcap\n");
//		exit(1);
//	}
//#endif
//
//	/* Retrieve the device list */
//	if (pcap_findalldevs(&alldevs, errbuf) == -1)
//	{
//		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
//		exit(1);
//	}
//
//	///* Print the list */
//	//for (d = alldevs; d; d = d->next)
//	//{
//	//	printf("%d. %s", ++i, d->name);
//	//	if (d->description)
//	//		printf(" (%s)\n", d->description);
//	//	else
//	//		printf(" (No description available)\n");
//	//}
//
//	/*if (i == 0)
//	{
//		printf("\nNo interfaces found! Make sure Npcap is installed.\n");
//		return -1;
//	}*/
//
//	/*printf("Enter the interface number (1-%d):", i);
//	scanf_s("%d", &inum);
//
//	std::cout << inum << std::endl;
//
//	scanf_s("%d", &inum);*/
//
//	inum = 4;
//
//	//if (inum < 1 || inum > i)
//	//{
//	//	printf("\nInterface number out of range.\n");
//	//	/* Free the device list */
//	//	pcap_freealldevs(alldevs);
//	//	return -1;
//	//}
//
//	/* Jump to the selected adapter */
//	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);
//
//	/* Open the device */
//	/* Open the adapter */
//	if ((adhandle = pcap_open_live(d->name,	// name of the device
//		65536,			// portion of the packet to capture.
//		// 65536 grants that the whole packet will be captured on all the MACs.
//		1,				// promiscuous mode (nonzero means promiscuous)
//		1000,			// read timeout
//		errbuf			// error buffer
//	)) == NULL)
//	{
//		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", d->name);
//		/* Free the device list */
//		pcap_freealldevs(alldevs);
//		return -1;
//	}
//
//	printf("listening on %s...\n", d->description);
//
//	/* At this point, we don't need any more the device list. Free it */
//	pcap_freealldevs(alldevs);
//	int netmask;
//	if (d->addresses != NULL)
//		/* Retrieve the mask of the first address of the interface */
//		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
//	else
//		/* If the interface is without an address
//		 * we suppose to be in a C class network */
//		netmask = 0xffffff;
//
//	//compile the filter
//	if (pcap_compile(adhandle, &fcode, "udp", 1, netmask) < 0)
//	{
//		fprintf(stderr,
//			"\nUnable to compile the packet filter. Check the syntax.\n");
//		/* Free the device list */
//		pcap_freealldevs(alldevs);
//		return -1;
//	}
//
//	//set the filter
//	if (pcap_setfilter(adhandle, &fcode) < 0)
//	{
//		fprintf(stderr, "\nError setting the filter.\n");
//		/* Free the device list */
//		pcap_freealldevs(alldevs);
//		return -1;
//	}
//
//	/* start the capture */
//	pcap_loop(adhandle, 0, packet_handler, NULL);
//
//	pcap_close(adhandle);

	std::string res = exec("netstat -aon");

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

	std::string tasklist = exec("tasklist");
	for (std::vector<std::string>& arr : data) {
		std::string pid = arr.at(arr.size() - 1);

		int pos = tasklist.find(pid) - 1;

		if (pos < 0) {
			arr.push_back("unknown");
			continue;
		}

		while (tasklist.at(pos) == ' ') {
			pos--;
		}

		std::string name = "";

		while (tasklist.at(pos) != '\n') {
			name = tasklist.at(pos) + name;
			pos--;
		}

		arr.push_back(name);
	}

	for (std::vector<std::string> arr : data) {
		std::cout << "line: ";
		for (std::string s : arr) {
			std::cout << s << ", ";
		}
		std::cout << std::endl;
	}

	return 0;
}