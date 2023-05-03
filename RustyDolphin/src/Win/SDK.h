#pragma once

#include <map>
#include <string>
#include <WinSock2.h>
#include <iphlpapi.h>
#include <json.hpp>

using json = nlohmann::ordered_json;

class SDK {
public:
	static std::string ipAddress;
	static void findIP(char* adName);
	static std::string exec(const char* cmd);
	static void init();
	static void release();
	static DWORD getPIDFromPort(DWORD port);
	static std::string getProcFromPID(DWORD PID);
	static std::string getProcFromPort(DWORD port);
	static json geoLocate(std::string addr);
	static std::vector<std::string> traceRoute(std::string addr);
	static std::vector<json> geoTrace(std::string addr);

private:
	static std::map<DWORD, DWORD> PORT2PID;
	static std::map<DWORD, std::string> PID2PROC;

	// tracert stuff

	static HANDLE hIcmpFile;
	static DWORD dwRetVal;
	static char* SendData;
	static LPVOID ReplyBuffer;
	static DWORD ReplySize;
	static IP_OPTION_INFORMATION ipOptions;

	static void initPIDCache();
	static void initICMP();
	static void refreshTables();
	static PMIB_TCPTABLE_OWNER_PID getTCPTable();
	static void refreshTCP();
	static PMIB_UDPTABLE_OWNER_PID getUDPTable();
	static void refreshUDP();
};