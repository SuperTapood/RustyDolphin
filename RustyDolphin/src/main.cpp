#include <iostream>
#include <cstdio>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <winsock2.h>
#include <windows.h>
#include "Base/Base.h"
#include "Networks/Networks.h"
#include "Win/Win.h"
#include <cstdint>

#define ETH_ALEN 6
#define ETHERTYPE_IP 0x0800

void free() {
	Logger::free();
	Capture::free();
}

void init() {
	atexit(free);
	Logger::init();
	Capture::init();
}

struct ether_header
{
	uint8_t   ether_dhost[ETH_ALEN];    /* destination eth addr */
	uint8_t   ether_shost[ETH_ALEN];    /* source ether addr    */
	uint16_t  ether_type;               /* packet type ID field */
};

struct tcphdr {
	uint16_t source;
	uint16_t dest;
	uint32_t seq;
	uint32_t ack_seq;
	uint16_t res1 : 4;
	uint16_t doff : 4;
	uint16_t fin : 1;
	uint16_t syn : 1;
	uint16_t rst : 1;
	uint16_t psh : 1;
	uint16_t ack : 1;
	uint16_t urg : 1;
	uint16_t res2 : 2;
	uint16_t window;
	uint16_t check;
	uint16_t urg_ptr;
};

void callback(int code, pcap_pkthdr* header, const u_char* pkt_data) {
	time_t local_tv_sec;
	struct tm timeinfo;
	char timestr[16];
	ip_header* ih;
	udp_header* uh;
	u_int ip_len;
	u_short sport;

	local_tv_sec = header->ts.tv_sec;
	localtime_s(&timeinfo, &local_tv_sec);
	strftime(timestr, sizeof(timestr), "%H:%M:%S", &timeinfo);

	struct ether_header* eth_header;
	eth_header = (struct ether_header*)pkt_data;
	long port = -1;
	int type = 0;

	if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
		ip_header* ip_hdr = (ip_header*)(pkt_data + sizeof(struct ether_header));
		if (ip_hdr->proto == IPPROTO_TCP) {
			struct tcphdr* tcp = (struct tcphdr*)(pkt_data + sizeof(struct ether_header) + sizeof(struct ip_header));
			port = ntohs(tcp->dest);
			type = 1;
		}
		else if (ip_hdr->proto == IPPROTO_UDP) {
			struct udp_header* udp = (struct udp_header*)(pkt_data + sizeof(struct ether_header) + sizeof(struct ip_header));
			port = ntohs(udp->dport);
			type = 2;
		}
		// printf("Port: %d\n", port);
	}

	///* retireve the position of the ip header */
	//ih = (ip_header*)(pkt_data +
	//	14); //length of ethernet header
	///* retireve the position of the udp header */
	//ip_len = (ih->ver_ihl & 0xf) * 4;
	//uh = (udp_header*)((u_char*)ih + ip_len);
	//sport = ntohs(uh->sport);
	std::string name;
	if (port == -1) {
		name = "fuck";
	}
	else {
		name = SDK::getProcFromPort(port);
	}
	// printf("%s,%.6d len:%d port:%d name:%s \n", timestr, header->ts.tv_usec, header->len, port, name);

	std::cout << "packet of port: " << port << " process: " << name  << "(type: " << type << ")" << std::endl;
}



int main()
{
	init();
	//std::cout << SDK::getProcFromPort(53411) << std::endl;
	//initPIDCache();
	//auto pTcpTable = getTcpTable();
	//// Print the TCP table
	//std::cout << "Num Entries: " << pTcpTable->dwNumEntries << std::endl;
	//for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
	//	auto& row = pTcpTable->table[i];
	//	std::cout << "Local Addr: " << ADDR2STR(row.dwLocalAddr) << ", Local Port: " << ntohs((u_short)row.dwLocalPort) << std::endl;
	//	std::cout << "Remote Addr: " << ADDR2STR(row.dwRemoteAddr) << ", Remote Port: " << ntohs((u_short)row.dwRemotePort) << std::endl;
	//	std::cout << "pid: " << row.dwOwningPid << " name: " << getNameFromPID(row.dwOwningPid) << std::endl;
	//}

	SDK::printTables();
	
	std::cout << SDK::getProcFromPort(8396) << std::endl;
	Capture::loop(3, callback, true);

	return 0;
	// std::cout << exec("curl -H") << std::endl;*/
	

	

	//// Free memory
	//free(pTcpTable);

	//return 0;
	/*pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fcode;*/

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
	//	// Print the list
	//	for (d = alldevs; d; d = d->next)
	//	{
	//		printf("%d. %s", ++i, d->name);
	//		if (d->description)
	//			printf(" (%s)\n", d->description);
	//		else
	//			printf(" (No description available)\n");
	//	}
	//
	//	if (i == 0)
	//	{
	//		printf("\nNo interfaces found! Make sure Npcap is installed.\n");
	//		return -1;
	//	}
	//
	//	printf("Enter the interface number (1-%d):", i);
	//	scanf_s("%d", &inum);
	//
	//	std::cout << inum << std::endl;
	//
	//	if (inum < 1 || inum > i)
	//	{
	//		printf("\nInterface number out of range.\n");
	//		/* Free the device list */
	//		pcap_freealldevs(alldevs);
	//		return -1;
	//	}
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

		//struct tm* ltime;
		//char timestr[16];
		//struct pcap_pkthdr* header;
		//const u_char* pkt_data;
		//time_t local_tv_sec;
		//int r;
		//struct tm timeinfo;

		//bool first = true;

		///* start the capture */
		//while ((r = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
		//	if (r == 0)
		//		/* Timeout elapsed */
		//		continue;

		//	std::cout << r << std::endl;

		//	/* convert the timestamp to readable format */
		//	local_tv_sec = header->ts.tv_sec;
		//	localtime_s(&timeinfo, &local_tv_sec);
		//	strftime(timestr, sizeof(timestr), "%H:%M:%S", &timeinfo);

		//	printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
		//}

		//pcap_close(adhandle);

	return 0;
}