// todo: fix the igmp thing for some reason it's parsing the wrong values from the packet

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

/*
* 
There are many possible protocol values that can be used in a packet. Some common protocol values include:

- ICMP (Internet Control Message Protocol): 1
- TCP (Transmission Control Protocol): 6
- UDP (User Datagram Protocol): 17
- IGMP (Internet Group Management Protocol): 2
- OSPF (Open Shortest Path First): 89
- GRE (Generic Routing Encapsulation): 47
- ESP (Encapsulating Security Payload): 50
- AH (Authentication Header): 51

These are just a few examples of the many possible protocol values that can be used in a packet. The protocol value tells the system how to treat the incoming packet.

Is there anything else you would like to know?

EtherType is a two-octet field in an Ethernet frame that is used to indicate which protocol is encapsulated in the payload of the frame. It is used at the receiving end by the data link layer to determine how the payload is processed. The same field is also used to indicate the size of some Ethernet frames².

Some common EtherType values include:

- IPv4: 0x0800
- ARP: 0x0806
- Wake-on-LAN: 0x0842
- VLAN-tagged frame (IEEE 802.1Q) and Shortest Path Bridging IEEE 802.1aq: 0x8100
- IPv6: 0x86DD
- MPLS unicast: 0x8847
- MPLS multicast: 0x8848

These are just a few examples of the many possible EtherType values that can be used in an Ethernet frame.

Is there anything else you would like to know?

Source: Conversation with Bing, 04/04/2023(1) EtherType - Wikipedia. https://en.wikipedia.org/wiki/EtherType Accessed 04/04/2023.
(2) Ether - Wikipedia. https://en.wikipedia.org/wiki/Ether Accessed 04/04/2023.
(3) EtherType - NETWORX SECURITY. https://www.networxsecurity.org/members-area/glossary/e/ethertype.html Accessed 04/04/2023.
*/

#define ETH_ALEN 6
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IPV6 0x86DD

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

void callback(pcap_pkthdr* header, const u_char* pkt_data) {
	u_int ip_len;
	u_short sport;

	struct ether_header* eth_header;
	eth_header = (struct ether_header*)pkt_data;
	long dport = -1, srport = -1;
	int type = 0;
	ip_header* ip_hdr = nullptr;

	auto p = fromRaw(header, pkt_data);

	//if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV4) {
	//	ip_hdr = (ip_header*)(pkt_data + sizeof(struct ether_header));
	//	if (ip_hdr->proto == IPPROTO_TCP) {
	//		u_char a = pkt_data[34];
	//		u_char b = pkt_data[35];
	//		srport = (a << 8) | b;
	//		a = pkt_data[36];
	//		b = pkt_data[37];
	//		dport = (a << 8) | b;
	//		type = 6;
	//	}
	//	else if (ip_hdr->proto == IPPROTO_UDP) {
	//		u_char a = pkt_data[34];
	//		u_char b = pkt_data[35];
	//		srport = (a << 8) | b;
	//		a = pkt_data[36];
	//		b = pkt_data[37];
	//		dport = (a << 8) | b;
	//		type = 17;
	//	}
	//	else {
	//		type = int(ip_hdr->proto);
	//	}
	//	// printf("Port: %d\n", port);
	//} 
	//else {
	//	if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP || ntohs(eth_header->ether_type) == ETHERTYPE_IPV6) {
	//		std::cout << "i know this guy!\n";
	//		return;
	//	}
	//	std::stringstream ss;
	//	ss << std::hex << eth_header->ether_type;
	//	auto s = ss.str();
	//	std::reverse(s.begin(), s.end());
	//	if (s.length() == 3) {
	//		s = "0" + s;
	//	}
	//	std::cout << "what the fuck is this protocol: 0x" << s << std::endl;
	//	return;
	//}

	///* retireve the position of the ip header */
	//ih = (ip_header*)(pkt_data +
	//	14); //length of ethernet header
	///* retireve the position of the udp header */
	//ip_len = (ih->ver_ihl & 0xf) * 4;
	//uh = (udp_header*)((u_char*)ih + ip_len);
	//sport = ntohs(uh->sport);
	/*std::string name;
	std::stringstream ss;
	ss << (ip_hdr->proto);
	if (srport == -1) {
		name = type == 0 ? ss.str() : "fuck";
	}
	else {
		name = SDK::getProcFromPort(srport);
		if (name == "<UNKNOWN>") {
			name = SDK::getProcFromPort(dport);
		}
	}*/
	// printf("%s,%.6d len:%d port:%d name:%s \n", timestr, header->ts.tv_usec, header->len, port, name);

	/*if (type == 6 || type == 17) {
		return;
	}*/
	/*std::cout << p.time << " packet of type " << type << " sport: " << srport << " and dport : " << dport << "process : " << name << " (type : " << type << ")" << std::endl;*/
	std::cout << p->toString() << std::endl;
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

	// SDK::printTables();
	
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