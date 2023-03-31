#pragma once

#include <iostream>
#include <fstream>

class Logger {
private:
	static std::ofstream file;
public:
	// club pinguin is kil
	// no
	Logger() = delete;
	static void init();
	static void log(std::string str);
	static void free();
};
