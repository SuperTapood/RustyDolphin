#pragma once

#include <ctime>
#include <WinSock2.h>
#include <pcap.h>
#include <string>


class Packet {
public:
	// header stuff
	std::string time;
	time_t epoch;
	int len;

	// ether stuff
	std::string phyDst;
	std::string phySrc;
	int type;
	const u_char* pkt_data;

private:
	std::string padDate(int t);

protected:
	std::string parseMAC(int start, int end);
	std::string parseIPV4(int start, int end);
	std::string parseIPV6(int start, int end);

public:
	Packet(pcap_pkthdr* header, const u_char* pkt_data);
	virtual std::string toString();
};