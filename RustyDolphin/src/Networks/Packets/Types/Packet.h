#pragma once

#include <memory>
#include <string>
#include <json.hpp>
#include <type_traits>
#include <pcap.h>
#include <iostream>
#include <sstream>
#include <ctime>


#include "Eth/BasePacket.h"

using json = nlohmann::ordered_json;

#define if_is(A) if constexpr(std::is_same_v<T, A>)

template <typename T>
class Packet {
public:
	const unsigned char* m_pktData;
	double m_time;
	std::string m_timeStr;
	int m_len;

	T m_data;

	Packet(pcap_pkthdr* header, const u_char* pkt_data) {
		m_pktData = pkt_data;
		timeval val = header->ts;
		m_time = val.tv_sec + (val.tv_usec / 1e6);

		struct tm timeinfo;
		auto m_epoch = (time_t)header->ts.tv_sec;
		localtime_s(&timeinfo, &m_epoch);
		std::stringstream ss;
		int year = 1900 + timeinfo.tm_year;
		int month = 1 + timeinfo.tm_mon;

		ss << year << "/" << padDate(month) << "/" << padDate(timeinfo.tm_mday) << " " << padDate(timeinfo.tm_hour) << ":" << padDate(timeinfo.tm_min) << ":" << padDate(timeinfo.tm_sec);
		std::memcpy(&m_data, pkt_data, sizeof(T));

		m_timeStr = ss.str();


		// endian bullshit
		if_is(BasePacket) {
			auto p = (BasePacket)m_data;
			p.m_type = htonl(p.m_type);
		}
	}

	std::string padDate(int t) {
		std::stringstream ss;
		ss << t;
		auto s = ss.str();

		if (s.length() < 2) {
			return "0" + s;
		}

		return s;
	}

	virtual std::string toString() {
		std::stringstream ss;
		if_is(BasePacket) {
			auto p = (BasePacket)m_data;
			ss << "Base Packet at " << m_timeStr << " of len " << m_len << " type: " << p.m_type << " from " << MAC2STR(p.m_phySrc) << " to " << MAC2STR(p.m_phyDst) << "\n";
		}
		return ss.str();
	}

	std::string MAC2STR(u_char* mac) {
		std::stringstream ss;
		for (int i = 0; i < 5; i++) {
			ss << std::setfill('0') << std::setw(2) << std::hex << (int)mac[i] << ":";
		}
		ss << std::setfill('0') << std::setw(2) << std::hex << (int)mac[5];

		return ss.str();
	}
};