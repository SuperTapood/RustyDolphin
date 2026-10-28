#include "Logger.h"

#include <iostream>

// average logger class

std::ofstream Logger::m_file;
std::mutex Logger::m_guard;

void Logger::init() {
	m_file = std::ofstream("log.txt");
}

void Logger::log(std::string str) {
	std::scoped_lock lock(m_guard);
	m_file << str << std::endl;
}

void Logger::release() {
	std::scoped_lock lock(m_guard);
	m_file.close();
}
