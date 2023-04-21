#include "Logger.h"

std::ofstream Logger::file;

void Logger::init() {
	file = std::ofstream("log.txt");
}

void Logger::log(std::string str) {
	std::cout << "log: " << str << std::endl;
	file << str << std::endl;
}

void Logger::free() {
	file.close();
}