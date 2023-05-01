#pragma once

#include <map>
#include <string>
#include <WinSock2.h>
#include <iphlpapi.h>

class SDK {
public:
	static std::string ipAddress;

	static std::string exec(const char* cmd);
	static void init();
	static void release();
	static void findIP(char* adName);
	static DWORD getPIDFromPort(DWORD port);
	static std::string getProcFromPID(DWORD PID);
	static std::string getProcFromPort(DWORD port);

private:
	static std::map<DWORD, DWORD> PORT2PID;
	static std::map<DWORD, std::string> PID2PROC;

	static void initPIDCache();
	static void refreshTables();
	static PMIB_TCPTABLE_OWNER_PID getTCPTable();
	static void refreshTCP();
	static PMIB_UDPTABLE_OWNER_PID getUDPTable();
	static void refreshUDP();
};