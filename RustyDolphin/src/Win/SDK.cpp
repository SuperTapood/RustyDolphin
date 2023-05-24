#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include "SDK.h"

#include "../Base/Logger.h"
#include "../Base/Data.h"

#include <string>
#include <array>
#include <memory>
#include <Psapi.h>
#include <vector>
#include <tchar.h>
#include <iostream>
#include <memory>
#include <string.h>
#include <sstream>
#include <IcmpAPI.h>
#include <fstream>
#include <cstring>

std::map<DWORD, DWORD> SDK::PORT2PID;
std::map<DWORD, std::string> SDK::PID2PROC;
HANDLE SDK::icmpHandle;
DWORD SDK::dwRetVal;
char* SDK::sendData;
LPVOID SDK::replyBuffer;
DWORD SDK::replySize;
IP_OPTION_INFORMATION SDK::ipOptions;
std::map<std::string, std::string> SDK::MACS;
std::string SDK::ipAddress;

std::string SDK::exec(const char* cmd) {
	std::array<char, 128> buffer{};
	std::string result;
	std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(cmd, "rt"), &_pclose);
	if (!pipe) {
		Logger::log("popen() failed!");
		exit(1);
	}

	while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
		result += buffer.data();
	}
	return result;
}

json SDK::geoLocate(std::string addr) {
	// we use curl and ask a 3rd party site to locate the address for us
	std::string cmd = R"(curl -s -H "User-Agent: keycdn-tools:https://amalb.iscool.co.il/" "https://tools.keycdn.com/geo.json?host=")";
	cmd += addr;
	auto res = SDK::exec(cmd.c_str());
	auto j = json::parse(res);

	return j;
}

void SDK::initPIDCache() {
	std::string tasklist = exec("tasklist");
	size_t pos;
	size_t p;
	while (true) {
		size_t ps = tasklist.find(" Services");
		size_t pc = tasklist.find(" Console");
		std::string str;
		if (ps == std::string::npos) {
			if (pc == std::string::npos) {
				break;
			}
			str = " Console";
			p = pc;
		}
		else {
			if (pc == std::string::npos) {
				str = " Services";
				p = ps;
			}
			else {
				if (pc < ps) {
					str = " Console";
					p = pc;
				}
				else {
					str = " Services";
					p = ps;
				}
			}
		}
		pos = p;
		pos -= 1;
		DWORD pid = 0;
		int len = 0;
		while (isdigit(tasklist.at(pos))) {
			pid += (int(tasklist.at(pos)) - 48) * std::pow(10, len++);
			pos--;
		}

		for (; tasklist.at(pos) == ' '; pos--);

		std::string name = "";
		while (tasklist.at(pos) != '\n') {
			name = tasklist.at(pos) + name;
			pos--;
		}

		if (!PID2PROC.contains(pid)) {
			PID2PROC.try_emplace(pid, name);
		}

		tasklist.erase(0, p + str.length());
	}
}

PMIB_TCPTABLE_OWNER_PID SDK::getTCPTable() {
	DWORD dwSize = 0;
	PMIB_TCPTABLE_OWNER_PID tcpTable = nullptr;

	// get the needed size of the buffer
	if (GetExtendedTcpTable(nullptr, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER) {
		std::cerr << "Failed to get required buffer size" << std::endl;
		return nullptr;
	}

	// allocate memory
	tcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(dwSize);
	if (tcpTable == nullptr) {
		std::cerr << "Failed to allocate memory for TCP table" << std::endl;
		return nullptr;
	}

	// actually fetch the table
	if (GetExtendedTcpTable(tcpTable, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
		std::cerr << "Failed to get TCP table" << std::endl;
		free(tcpTable);
		return nullptr;
	}

	return tcpTable;
}

void SDK::refreshTCP() {
	auto table = SDK::getTCPTable();

	for (DWORD i = 0; i < table->dwNumEntries; i++) {
		auto const& row = table->table[i];
		u_short port = ntohs((u_short)row.dwLocalPort);
		DWORD pid = row.dwOwningPid;
		PORT2PID.insert({ port, pid });
	}

	free(table);
}

PMIB_UDPTABLE_OWNER_PID SDK::getUDPTable() {
	DWORD dwSize = 0;
	PMIB_UDPTABLE_OWNER_PID udpTable = nullptr;

	// get the required buffer size
	if (GetExtendedUdpTable(nullptr, &dwSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) != ERROR_INSUFFICIENT_BUFFER) {
		std::cerr << "Failed to get required buffer size" << std::endl;
		return nullptr;
	}

	// allocate memory
	udpTable = (PMIB_UDPTABLE_OWNER_PID)malloc(dwSize);
	if (udpTable == NULL) {
		std::cerr << "Failed to allocate memory for TCP table" << std::endl;
		return nullptr;
	}

	// get the table
	if (GetExtendedUdpTable(udpTable, &dwSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) != NO_ERROR) {
		std::cerr << "Failed to get UDP table" << std::endl;
		free(udpTable);
		return nullptr;
	}

	return udpTable;
}

void SDK::refreshUDP() {
	auto table = SDK::getUDPTable();

	for (DWORD i = 0; i < table->dwNumEntries; i++) {
		auto& row = table->table[i];
		u_short port = ntohs((u_short)row.dwLocalPort);
		DWORD pid = row.dwOwningPid;
		PORT2PID.insert({ port, pid });
	}

	free(table);
}

void SDK::refreshTables() {
	refreshTCP();
	refreshUDP();
}

void SDK::findIP(char* adName) {
	ULONG buffer_size = sizeof(IP_ADAPTER_INFO);
	IP_ADAPTER_INFO* adapter_info = (IP_ADAPTER_INFO*)malloc(buffer_size);

	// get adapter info
	if (GetAdaptersInfo(adapter_info, &buffer_size) == ERROR_BUFFER_OVERFLOW) {
		free(adapter_info);
		adapter_info = (IP_ADAPTER_INFO*)malloc(buffer_size);
		GetAdaptersInfo(adapter_info, &buffer_size);
	}

	std::stringstream ss;

	std::string ad = adName;
	int i = 0;

	for (; i < ad.size(); i++) {
		if (ad.at(i) == '_') {
			i++;
			break;
		}
	}

	for (; i < ad.size(); i++) {
		ss << ad.at(i);
	}

	ad = ss.str();

	// find the right ip address
	for (IP_ADAPTER_INFO* adapter = adapter_info; adapter != nullptr; adapter = adapter->Next) {
		if ((adapter->AdapterName) == ad) {
			ipAddress = adapter->IpAddressList.IpAddress.String;
			break;
		}
	}

	free(adapter_info);
}

void SDK::initICMP() {
	dwRetVal = 0;
	std::string temp = "Data Buffer";
	sendData = new char[temp.size() + 1];
	std::ranges::copy(temp.begin(), temp.end(), sendData);
	sendData[temp.size()] = '\0';
	replyBuffer = nullptr;
	replySize = 0;
	ipOptions = { 0 };

	// create handle
	icmpHandle = IcmpCreateFile();
	if (icmpHandle == INVALID_HANDLE_VALUE) {
		printf("Unable to open ICMP handle\n");
		exit(1);
	}

	// set reply buffer size
	replySize = sizeof(ICMP_ECHO_REPLY) + sizeof(sendData);
	replyBuffer = malloc(replySize);
	if (replyBuffer == NULL) {
		printf("Unable to allocate memory for reply buffer\n");
		exit(1);
	}
}

void SDK::init() {
	initPIDCache();
	refreshTables();
	initICMP();

	// load the manuf file into memory
	std::ifstream manuf("deps/manuf/manuf");
	std::string line;

	while (getline(manuf, line)) {
		auto addr = line.substr(0, 8);
		auto firstTab = line.find("\t");
		auto secondTab = line.rfind("\t");
		auto name = line.substr(firstTab + 1, secondTab - firstTab - 1);

		MACS.try_emplace(addr, name);
	}

	MACS.try_emplace("33:33:00", "IPV6mcast");
}

void SDK::release() {
	if (replyBuffer != NULL) {
		free(replyBuffer);
	}
	IcmpCloseHandle(icmpHandle);
}

DWORD SDK::getPIDFromPort(DWORD port) {
	if (PORT2PID.contains(port)) {
		return PORT2PID.at(port);
	}

	// if we can't find the port, refresh the tables
	refreshTables();

	if (PORT2PID.contains(port)) {
		return PORT2PID.at(port);
	}

	return MAXDWORD;
}

std::string SDK::getProcFromPID(DWORD PID) {
	if (PID == MAXDWORD) {
		// pid doesn't exist
		return "<UNKNOWN>";
	}

	if (PID2PROC.contains(PID)) {
		// we figured out this pid already
		return PID2PROC.at(PID);
	}

	TCHAR procName[MAX_PATH] = _T("4");
	HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, PID);

	if (proc == nullptr) {
		// couldn't open the process
		return "<BADPROCESS>";
	}

	if (!GetModuleBaseName(proc, nullptr, procName, sizeof(procName))) {
		// process has not name
		return "<NAMELESS>";
	}

	std::string processName;

	// comvert TCHAR to std string :)
	int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, procName, -1, nullptr, 0, nullptr, nullptr);
	std::vector<char> buffer(sizeNeeded);
	WideCharToMultiByte(CP_UTF8, 0, procName, -1, &buffer[0], sizeNeeded, nullptr, nullptr);
	processName.assign(buffer.begin(), buffer.end() - 1); // remove the null terminator

	// close the handle we opened
	CloseHandle(proc);

	// cache the results
	PID2PROC.try_emplace(PID, processName);

	return processName;
}

std::string SDK::getProcFromPort(DWORD port) {
	return getProcFromPID(getPIDFromPort(port));
}

std::vector<std::string> SDK::traceRoute(std::string addr) {
	unsigned long ipaddr = INADDR_NONE;
	// IP address string to binary
	ipaddr = inet_addr(addr.c_str());
	if (ipaddr == INADDR_NONE) {
		printf("Unable to parse IP address\n");
		exit(1);
	}

	u_char ttl = 1;
	std::vector<std::string> addrs;

	while (ttl < 60) {
		if (Data::geoTerminate) {
			return addrs;
		}
		ipOptions.Ttl = ttl++;
		// send ICMP echo request
		dwRetVal = IcmpSendEcho(icmpHandle, ipaddr, sendData, sizeof(sendData),
			&ipOptions, replyBuffer, replySize, 100);
		if (dwRetVal != 0) {
			PICMP_ECHO_REPLY echoReply = (PICMP_ECHO_REPLY)replyBuffer;
			struct in_addr replyAddr;
			replyAddr.S_un.S_addr = echoReply->Address;
			addrs.emplace_back(inet_ntoa(replyAddr));

			if (echoReply->Status == 0 || inet_ntoa(replyAddr) == addr) {
				break;
			}
		}
		// nothing to do if the icmp fails
		//else {
		//	DWORD errorMessageID = GetLastError();

		//	LPSTR messageBuffer = NULL;
		//	size_t size = FormatMessageA(
		//		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		//		NULL,
		//		errorMessageID,
		//		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		//		(LPSTR)&messageBuffer,
		//		0,
		//		NULL
		//	);
		//	std::stringstream ss;
		//	ss << "error: " << messageBuffer;
		//	//addrs.push_back(ss.str());
		//	LocalFree(messageBuffer);
		//}
	}

	return addrs;
}

void SDK::geoTrace(std::string addr) {
	Data::hopAddr = addr;
	Data::geoDone = false;
	Data::geoState = 1;
	auto vec = traceRoute(addr);
	Data::geoState = 2;

	for (const auto& add : vec) {
		if (Data::geoTerminate) {
			return;
		}
		auto j = geoLocate(add);
		{
			std::scoped_lock guard(Data::geoGuard);
			Data::locs.emplace_back(j);
		}
	}

	if (Data::locs.empty()) {
		Data::geoState = 3;
	}
	else {
		Data::geoState = 4;
	}
	Data::geoDone = true;
}

std::string SDK::lookupMAC(std::string addr) {
	std::ranges::transform(addr.begin(), addr.end(), addr.begin(),
		[](unsigned char c) { return std::toupper(c); });

	if (MACS.contains(addr)) {
		return std::format("{}_", MACS.at(addr));
	}
	std::ranges::transform(addr.begin(), addr.end(), addr.begin(),
		[](unsigned char c) { return std::tolower(c); });

	return std::format("{}:", addr);
}