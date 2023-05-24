#include "Logger.h"

#include <iostream>

// average logger class

std::ofstream Logger::m_file;

void Logger::init() {
	m_file = std::ofstream("log.txt");
}

void Logger::log(std::string str) {
	m_file << str << std::endl;
}

void Logger::release() {
	m_file.close();
}