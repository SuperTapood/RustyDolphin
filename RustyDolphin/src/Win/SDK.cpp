#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include "SDK.h"

#include "../Base/Logger.h"

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
// #include "../base/Structs.h"

std::map<DWORD, DWORD> SDK::PORT2PID;
std::map<DWORD, std::string> SDK::PID2PROC;
std::string SDK::ipAddress;
HANDLE SDK::hIcmpFile;
DWORD SDK::dwRetVal;
char* SDK::SendData;
LPVOID SDK::ReplyBuffer;
DWORD SDK::ReplySize;
IP_OPTION_INFORMATION SDK::ipOptions;

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
	PMIB_TCPTABLE_OWNER_PID pTcpTable = nullptr;

	// Get the required buffer size
	if (GetExtendedTcpTable(nullptr, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER) {
		std::cerr << "Failed to get required buffer size" << std::endl;
		return nullptr;
	}

	// Allocate memory for the TCP table
	pTcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(dwSize);
	if (pTcpTable == NULL) {
		std::cerr << "Failed to allocate memory for TCP table" << std::endl;
		return nullptr;
	}

	// Get the TCP table
	if (GetExtendedTcpTable(pTcpTable, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
		std::cerr << "Failed to get TCP table" << std::endl;
		free(pTcpTable);
		return nullptr;
	}

	return pTcpTable;
}

void SDK::refreshTCP() {
	auto table = SDK::getTCPTable();

	for (DWORD i = 0; i < table->dwNumEntries; i++) {
		auto const& row = table->table[i];
		u_short port = ntohs((u_short)row.dwLocalPort);
		DWORD pid = row.dwOwningPid;
		if (!PORT2PID.contains(port)) {
			PORT2PID.insert({ port, pid });
		}
	}
}

PMIB_UDPTABLE_OWNER_PID SDK::getUDPTable() {
	DWORD dwSize = 0;
	PMIB_UDPTABLE_OWNER_PID pUdpTable = nullptr;

	// Get the required buffer size
	if (GetExtendedUdpTable(nullptr, &dwSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) != ERROR_INSUFFICIENT_BUFFER) {
		std::cerr << "Failed to get required buffer size" << std::endl;
		return nullptr;
	}

	// Allocate memory for the TCP table
	pUdpTable = (PMIB_UDPTABLE_OWNER_PID)malloc(dwSize);
	if (pUdpTable == NULL) {
		std::cerr << "Failed to allocate memory for TCP table" << std::endl;
		return nullptr;
	}

	// Get the TCP table
	if (GetExtendedUdpTable(pUdpTable, &dwSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) != NO_ERROR) {
		std::cerr << "Failed to get UDP table" << std::endl;
		free(pUdpTable);
		return nullptr;
	}

	return pUdpTable;
}

void SDK::refreshUDP() {
	auto table = SDK::getUDPTable();

	for (DWORD i = 0; i < table->dwNumEntries; i++) {
		auto& row = table->table[i];
		u_short port = ntohs((u_short)row.dwLocalPort);
		DWORD pid = row.dwOwningPid;
		PORT2PID.insert({ port, pid });
	}
}

void SDK::refreshTables() {
	refreshTCP();
	refreshUDP();
}

void SDK::findIP(char* adName) {
	ULONG buffer_size = sizeof(IP_ADAPTER_INFO);
	IP_ADAPTER_INFO* adapter_info = (IP_ADAPTER_INFO*)malloc(buffer_size);

	// Get the adapter information
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

	// Print the IP addresses
	for (IP_ADAPTER_INFO* adapter = adapter_info; adapter != nullptr; adapter = adapter->Next) {
		/*std::cout << "Adapter name: " << adapter->AdapterName << std::endl;
		std::cout << "IP address: " << adapter->IpAddressList.IpAddress.String << std::endl;
		std::cout << "Subnet mask: " << adapter->IpAddressList.IpMask.String << std::endl;
		std::cout << std::endl;*/
		if ((adapter->AdapterName) == ad) {
			ipAddress = adapter->IpAddressList.IpAddress.String;
			break;
		}
	}

	free(adapter_info);
}

void SDK::initICMP() {
	// Initialize variables
	dwRetVal = 0;
	std::string temp = "Data Buffer";
	SendData = new char[temp.size() + 1];
	std::ranges::copy(temp.begin(), temp.end(), SendData);
	SendData[temp.size()] = '\0';
	ReplyBuffer = nullptr;
	ReplySize = 0;
	ipOptions = { 0 };

	// Open ICMP handle
	hIcmpFile = IcmpCreateFile();
	if (hIcmpFile == INVALID_HANDLE_VALUE) {
		printf("Unable to open ICMP handle\n");
		exit(1);
	}

	// Set reply buffer size
	ReplySize = sizeof(ICMP_ECHO_REPLY) + sizeof(SendData);
	ReplyBuffer = (VOID*)malloc(ReplySize);
	if (ReplyBuffer == NULL) {
		printf("Unable to allocate memory for reply buffer\n");
		exit(1);
	}
}

void SDK::init() {
	initPIDCache();
	refreshTables();
	initICMP();
}

void SDK::release() {
	// Cleanup
	if (ReplyBuffer != NULL) {
		free(ReplyBuffer);
	}
	IcmpCloseHandle(hIcmpFile);
}

DWORD SDK::getPIDFromPort(DWORD port) {
	if (PORT2PID.contains(port)) {
		return PORT2PID.at(port);
	}

	refreshTables();

	if (PORT2PID.contains(port)) {
		return PORT2PID.at(port);
	}

	return MAXDWORD;
}

std::string SDK::getProcFromPID(DWORD PID) {
	if (PID == MAXDWORD) {
		return "<UNKNOWN>";
	}

	if (PID2PROC.contains(PID)) {
		return PID2PROC.at(PID);
	}

	TCHAR szProcessName[MAX_PATH] = _T("4");
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, PID);

	if (hProcess == NULL) {
		return "<BADPROCESS>";
	}

	if (!GetModuleBaseName(hProcess, nullptr, szProcessName, sizeof(szProcessName))) {
		return "<NAMELESS>";
	}

	std::string processName;

	int size_needed = WideCharToMultiByte(CP_UTF8, 0, szProcessName, -1, NULL, 0, NULL, NULL);
	std::vector<char> buffer(size_needed);
	WideCharToMultiByte(CP_UTF8, 0, szProcessName, -1, &buffer[0], size_needed, NULL, NULL);
	processName.assign(buffer.begin(), buffer.end() - 1); // -1 to remove the null terminator

	CloseHandle(hProcess);

	PID2PROC.try_emplace(PID, processName);

	return processName;
}

std::string SDK::getProcFromPort(DWORD port) {
	return getProcFromPID(getPIDFromPort(port));
}

std::vector<std::string> SDK::traceRoute(std::string addr) {
	unsigned long ipaddr = INADDR_NONE;
	// Convert IP address string to binary
	ipaddr = inet_addr(addr.c_str());
	if (ipaddr == INADDR_NONE) {
		printf("Unable to parse IP address\n");
		exit(1);
	}

	u_char ttl = 1;
	std::vector<std::string> addrs;

	while (true) {
		ipOptions.Ttl = ttl++;
		// Send ICMP echo request
		dwRetVal = IcmpSendEcho(hIcmpFile, ipaddr, SendData, sizeof(SendData),
			&ipOptions, ReplyBuffer, ReplySize, 100);
		if (dwRetVal != 0) {
			PICMP_ECHO_REPLY pEchoReply = (PICMP_ECHO_REPLY)ReplyBuffer;
			struct in_addr ReplyAddr;
			ReplyAddr.S_un.S_addr = pEchoReply->Address;
			/*printf("Received %ld ICMP echo replies from %s\n", dwRetVal, inet_ntoa(ReplyAddr));
			printf("Status: %ld\n", pEchoReply->Status);
			printf("Round trip time: %ld milliseconds\n", pEchoReply->RoundTripTime);*/
			addrs.emplace_back(inet_ntoa(ReplyAddr));

			if (pEchoReply->Status == 0) {
				break;
			}
		}
		else {
			DWORD errorMessageID = GetLastError();

			LPSTR messageBuffer = NULL;
			size_t size = FormatMessageA(
				FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
				NULL,
				errorMessageID,
				MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
				(LPSTR)&messageBuffer,
				0,
				NULL
			);
			std::stringstream ss;
			ss << "error: " << messageBuffer;
			addrs.push_back(ss.str());
			LocalFree(messageBuffer);
		}
	}

	return addrs;
}

std::vector<json> SDK::geoTrace(std::string addr) {
	auto vec = traceRoute(addr);

	std::vector<json> locs;

	for (const auto& add : vec) {
		auto j = geoLocate(add);
		locs.emplace_back(j);
	}

	return locs;
}