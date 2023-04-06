#include "Packet.h"
#include <iostream>
#include <sstream>

#define MACSIZE 6


Packet::Packet(pcap_pkthdr* header, const u_char* pkt_data) {
	this->pkt_data = pkt_data;
	struct tm timeinfo;
	epoch = header->ts.tv_sec;
	localtime_s(&timeinfo, &epoch);
	std::stringstream ss;
	int year = 1900 + timeinfo.tm_year;
	int month = 1 + timeinfo.tm_mon;

	ss << year << "/" << padDate(month) << "/" << padDate(timeinfo.tm_mday) << " " << padDate(timeinfo.tm_hour) << ":" << padDate(timeinfo.tm_min) << ":" << padDate(timeinfo.tm_sec);
	m_time = ss.str();

	pos = 0;
	
	phyDst = parseMAC(&pos, pos + MACSIZE);

	phySrc = parseMAC(&pos, pos + MACSIZE);

	len = header->len;

	type = (int)parseLong(&pos, pos + 2);
}


std::string Packet::toString() {
	std::stringstream ss;

	ss << "Base Packet at " << m_time << " of len " << len << " type: " << type << " from " << phySrc << " to " << phyDst;

	return ss.str();
}

std::string Packet::padDate(int t) {
	std::stringstream ss;
	ss << t;
	auto s = ss.str();

	if (s.length() < 2) {
		return "0" + s;
	}

	return s;
}

std::string Packet::parseMAC(int* start, int end) {
	std::stringstream ss;
	std::string mac;

	ss << std::hex;

	for (; (*start) < end; (*start)++) {
		auto v = (int)pkt_data[(*start)];
		if (v < 10) {
			ss << "0";
		}
		ss << v << ":";
	}

	mac = ss.str();
	mac.pop_back();

	return mac;
}

std::string Packet::parseIPV4(int* start, int end) {
	std::string ip;
	std::stringstream ss;

	for (; (*start) < end; (*start)++) {
		ss << (int)pkt_data[(*start)] << ".";
	}

	ip = ss.str();
	ip.pop_back();

	return ip;
}

std::string Packet::parseIPV6(int* start, int end) {
	std::stringstream ss;
	std::string ip;

	ss << std::hex;

	for (; (*start) + 1 < end; (*start)++) {
		auto v1 = (int)pkt_data[(*start)];
		if (v1 < 10) {
			ss << "0";
		}
		auto v2 = (int)pkt_data[(*start) + 1];
		if (v2 < 10) {
			ss << "0";
		}
		ss << v1 << v2 << ":";
	}

	ip = ss.str();
	ip.pop_back();

	return ip;
}

long long Packet::parseLong(int* start, int end) {
	long long out = 0;
	int n = end - (*start);

	for (int i = 0; (*start) < end; (*start)++, i++) {
		out |= (long long)pkt_data[(*start)] << ((n - i - 1) * 8);
	}

	return out;
}