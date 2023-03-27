#include "winapi.h"

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
    size_t pos, p;
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
        // std::cout << "cached pid: " << pid << " found with value: " << Data::names.at(index) << std::endl;
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

PMIB_TCPTABLE_OWNER_PID getTcpTable() {
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

PMIB_UDPTABLE_OWNER_PID getUdpTable() {
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

