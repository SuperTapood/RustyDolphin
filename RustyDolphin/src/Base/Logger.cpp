#include "Logger.h"

#include <iostream>

std::ofstream Logger::m_file;

void Logger::init() {
	m_file = std::ofstream("log.txt");
}

void Logger::log(std::string str) {
	std::cout << "log: " << str << std::endl;
	m_file << str << std::endl;
}

void Logger::free() {
	m_file.close();
}