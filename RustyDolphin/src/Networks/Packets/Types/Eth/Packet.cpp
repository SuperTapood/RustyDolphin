#include "Packet.h"
#include <iostream>
#include <sstream>


Packet::Packet(pcap_pkthdr* header, const u_char* pkt_data) {
	this->pkt_data = pkt_data;
	struct tm timeinfo;
	epoch = header->ts.tv_sec;
	localtime_s(&timeinfo, &epoch);
	std::stringstream ss;
	int year = 1900 + timeinfo.tm_year;
	int month = 1 + timeinfo.tm_mon;

	ss << year << "/" << padDate(month) << "/" << padDate(timeinfo.tm_mday) << " " << padDate(timeinfo.tm_hour) << ":" << padDate(timeinfo.tm_min) << ":" << padDate(timeinfo.tm_sec);
	time = ss.str();

	len = header->len;
	u_char a = pkt_data[12];
	u_char b = pkt_data[13];
	type = (a << 8) | b;

	phyDst = parseMAC(0, 6);

	phySrc = parseMAC(6, 12);
}


std::string Packet::toString() {
	std::stringstream ss;

	ss << "Base Packet at " << time << " of len " << len << " type: " << type << " from " << phySrc << " to " << phyDst;

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

std::string Packet::parseMAC(int start, int end) {
	std::stringstream ss;
	std::string mac;

	ss << std::hex;

	for (int i = start; i < end; i++) {
		auto v = (int)pkt_data[i];
		if (v < 10) {
			ss << "0";
		}
		ss << v << ":";
	}

	mac = ss.str();
	mac.pop_back();

	return mac;
}

std::string Packet::parseIPV4(int start, int end) {
	std::string ip;
	std::stringstream ss;

	for (int i = start; i < end; i++) {
		unsigned int x;
		std::stringstream s;
		s << pkt_data[i];
		s >> x;
		ss << x << ".";
	}

	ip = ss.str();
	ip.pop_back();

	return ip;
}

std::string Packet::parseIPV6(int start, int end) {
	std::stringstream ss;
	std::string ip;

	ss << std::hex;

	for (int i = start; i + 1 < end; i++) {
		auto v1 = (int)pkt_data[i];
		if (v1 < 10) {
			ss << "0";
		}
		auto v2 = (int)pkt_data[i + 1];
		if (v2 < 10) {
			ss << "0";
		}
		ss << v1 << v2 << ":";
	}

	ip = ss.str();
	ip.pop_back();

	return ip;
}