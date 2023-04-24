#pragma once

#include <ctime>
#include <WinSock2.h>
#include <pcap.h>
#include <string>
#include <json.hpp>

using json = nlohmann::ordered_json;

class Packet {
public:
	// header stuff
	std::string m_time;
	time_t m_epoch;
	int m_len;

	// ether stuff
	std::string m_phyDst;
	std::string m_phySrc;
	int m_type;
	const u_char* m_pktData;

	Packet(pcap_pkthdr* header, const u_char* pkt_data);
	virtual ~Packet() = default;
	virtual std::string toString();
	virtual json jsonify();

protected:
	int pos;

	std::string parseMAC(int* start, int end);
	std::string parseIPV4(int* start, int end);
	std::string parseIPV6(int* start, int end);
	long long parseLong(int* start, int end);

private:
	std::string padDate(int t);
};