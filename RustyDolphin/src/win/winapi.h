#pragma once

#include <vector>
#include <map>
#include <iostream>
#include <WinSock2.h>
#include <tchar.h>
#include <array>
#include <string>
#include <string_view>
#include <Psapi.h>
#include <windows.h>
#include <iphlpapi.h>

std::string exec(const char* cmd);

void initPIDCache();

std::string getNameFromPID(DWORD pid);

PMIB_TCPTABLE_OWNER_PID getTcpTable();

PMIB_UDPTABLE_OWNER_PID getUdpTable();
