#include "SDK.h"

#include "../Base/Logger.h"

#include <string>
#include <array>
#include <memory>
#include <Psapi.h>
#include <vector>
#include <tchar.h>
#include "../base/Structs.h"

std::map<DWORD, DWORD> SDK::PORT2PID;
std::map<DWORD, std::string> SDK::PID2PROC;

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

		if (PID2PROC.count(pid) == 0) {
			PID2PROC.insert({ pid, name });
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
		auto& row = table->table[i];
		u_short port = ntohs((u_short)row.dwLocalPort);
		DWORD pid = row.dwOwningPid;
		if (PORT2PID.count(port) == 0) {
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

void SDK::init() {
	initPIDCache();
	refreshTables();
}

DWORD SDK::getPIDFromPort(DWORD port) {
	if (PORT2PID.count(port) > 0) {
		return PORT2PID.at(port);
	}

	//refreshTables();

	if (PORT2PID.count(port) > 0) {
		return PORT2PID.at(port);
	}

	return MAXDWORD;
}

std::string SDK::getProcFromPID(DWORD PID) {
	if (PID == MAXDWORD) {
		return "<UNKNOWN>";
	}

	if (PID2PROC.count(PID) == 1) {
		return PID2PROC.at(PID);
	}

	TCHAR szProcessName[MAX_PATH] = _T("4");
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, PID);

	if (hProcess == NULL) {
		return "<BADPROCESS>";
	}

	if (!GetModuleBaseName(hProcess, NULL, szProcessName, sizeof(szProcessName))) {
		return "<NAMELESS>";
	}

	std::string processName;

	int size_needed = WideCharToMultiByte(CP_UTF8, 0, szProcessName, -1, NULL, 0, NULL, NULL);
	std::vector<char> buffer(size_needed);
	WideCharToMultiByte(CP_UTF8, 0, szProcessName, -1, &buffer[0], size_needed, NULL, NULL);
	processName.assign(buffer.begin(), buffer.end() - 1); // -1 to remove the null terminator

	CloseHandle(hProcess);

	PID2PROC.insert({ PID, processName });

	return processName;
}

std::string SDK::getProcFromPort(DWORD port) {
	return getProcFromPID(getPIDFromPort(port));
}

void SDK::printTables() {
	auto pTcpTable = getTCPTable();

	// Print the TCP table
	std::cout << "Num Entries: " << pTcpTable->dwNumEntries << std::endl;
	for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
		auto& row = pTcpTable->table[i];
		std::cout << "Local Addr: " << ADDR2STR(row.dwLocalAddr) << ", Local Port: " << ntohs((u_short)row.dwLocalPort) << std::endl;
		std::cout << "Remote Addr: " << ADDR2STR(row.dwRemoteAddr) << ", Remote Port: " << ntohs((u_short)row.dwRemotePort) << std::endl;
		std::cout << "pid: " << row.dwOwningPid << " name: " << getProcFromPID(row.dwOwningPid) << std::endl;
	}

	// Free memory
	free(pTcpTable);

	auto pUdpTable = getUDPTable();

	// Print the UDP table
	std::cout << "Num Entries: " << pUdpTable->dwNumEntries << std::endl;
	for (DWORD i = 0; i < pUdpTable->dwNumEntries; i++) {
		auto& row = pUdpTable->table[i];

		std::cout << "Local Addr: " << ADDR2STR(row.dwLocalAddr) << ", Local Port: " << ntohs((u_short)row.dwLocalPort) << std::endl;
	}

	// Free memory
	free(pUdpTable);
}