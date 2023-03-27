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

class Data {
public:
    static std::vector<DWORD> pids;
    static std::vector<std::string> names;
};

std::vector<DWORD> Data::pids;
std::vector<std::string> Data::names;



std::string exec(const char* cmd) {
    std::array<char, 128> buffer{};
    std::string result;
    std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(cmd, "rt"), &_pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }

    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

void initPIDCache() {
    std::string tasklist = exec("tasklist");
    /*std::vector<std::string> procs{ "svchost.exe", "System Idle Process", "dasHost.exe", "nvcontainer.exe", "System", "lsass.exe", "wininit.exe", "spoolsv.exe", "services.exe", "lghub_updater.exe"};
    for (std::string proc : procs) {
        int pos = 0;
        std::string tasklist = tasks;
        while ((pos = tasklist.find(proc)) != std::string::npos) {
            pos += proc.length();
            for (; !isdigit(tasklist.at(pos)); pos++);
            
            DWORD pid = 0;
            while (isdigit(tasklist.at(pos))) {
                pid = (pid * 10) + int(tasklist.at(pos)) - 48;
                pos++;
            }

            processes[pid] = proc;
            tasklist.erase(0, pos);
        }
    }*/

    int pos, p;
    while (true) {
        int ps = tasklist.find("Services");
        int pc = tasklist.find("Console");
        std::string str;
        if (ps == std::string::npos) {
            if (pc == std::string::npos) {
                break;
            }
            str = "Console";
            p = pc;
        }
        else {
            str = "Services";
            p = ps;
        }
        pos = p;
        pos -= 2;
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

        Data::pids.push_back(pid);
        Data::names.push_back(name);
        tasklist.erase(0, p + str.length());
    }

    /*for (int i = 0; i < Data::pids.size(); i++)
    {
        std::cout << Data::pids.at(i) << " " << Data::names.at(i) << " " << "\n";
    }*/
}

std::string getNameFromPID(DWORD pid) {
    
    auto res = std::find(Data::pids.begin(), Data::pids.end(), pid);
    
    if (res != Data::pids.end()) {
        int index = res - Data::pids.begin();
        return Data::names.at(index);
    }

    TCHAR szProcessName[MAX_PATH] = _T("<unknown>");
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

    if (hProcess == NULL) {
        return "null handle";
    }

    if (!GetModuleBaseName(hProcess, NULL, szProcessName, sizeof(szProcessName))) {
        return "bad base name";
    }
    std::string processName;

    int size_needed = WideCharToMultiByte(CP_UTF8, 0, szProcessName, -1, NULL, 0, NULL, NULL);
    std::vector<char> buffer(size_needed);
    WideCharToMultiByte(CP_UTF8, 0, szProcessName, -1, &buffer[0], size_needed, NULL, NULL);
    processName.assign(buffer.begin(), buffer.end() - 1); // -1 to remove the null terminator

    CloseHandle(hProcess);
    return processName;
}