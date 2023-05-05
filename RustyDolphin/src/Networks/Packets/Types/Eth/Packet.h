#pragma once

#include <ctime>
#include <WinSock2.h>
#include <pcap.h>
#include <string>
#include <json.hpp>

using json = nlohmann::ordered_json;

class Packet {
public:
	unsigned int idx;

	unsigned int pos = 0;
	// header stuff
	std::string m_time;
	time_t m_epoch;
	unsigned int m_len;

	// ether stuff
	std::string m_phyDst;
	std::string m_phySrc;
	unsigned short m_type;
	std::string m_strType;
	const u_char* m_pktData;

	Packet(pcap_pkthdr* header, const u_char* pkt_data, unsigned int idx);
	virtual ~Packet() = default;
	virtual void render();
	virtual std::string toString();
	virtual json jsonify();

protected:

	std::string parseMAC(unsigned int size = 6);
	std::string parseIPV4(unsigned int size = 4);
	std::string parseIPV6(unsigned int size = 16);
	std::string parse(unsigned long long size);
	long long parseLongLong();
	long parseLong();
	int parseInt();
	short parseShort();
	/*double parseDouble();
	float parseFloat();*/

private:
	std::string padDate(int t);
	uint64_t htonll(uint64_t x);
	int htoni(int x);
};