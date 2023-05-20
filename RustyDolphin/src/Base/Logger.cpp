#include "Logger.h"

#include <iostream>
#include <cassert>

std::ofstream Logger::m_file;

void Logger::init() {
	m_file = std::ofstream("log.txt");
}

void Logger::log(std::string str) {
	std::cout << "log: " << str << std::endl;
	//assert(false);
	m_file << str << std::endl;
}

void Logger::release() {
	m_file.close();
}