#include "capture.h"

#include <pcap.h>
#include "structs.h"
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

#include <pcap.h>

#include <stdio.h>
#include <time.h>
#include <tchar.h>
#include <iostream>

BOOL LoadNpcapDlls()
{
	_TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}
	return TRUE;
}

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

	if (true) {
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
		printf("param - %s\n", param);
		printf("data - %s\n", pkt_data);
	}
}