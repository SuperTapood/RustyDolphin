#include "Logger.h"

std::ofstream Logger::file;

void Logger::init() {
	file = std::ofstream("log.txt");
}

void Logger::log(std::string str) {
	file << str << std::endl;
}

void Logger::free() {
	file.close();
}