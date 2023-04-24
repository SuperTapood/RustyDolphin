#pragma once

#include <fstream>

/// <summary>
/// Static logging class
/// </summary>
class Logger {
public:
	// club pinguin is kil
	// no
	Logger() = delete;
	/// <summary>
	/// init the logger
	/// </summary>
	static void init();
	/// <summary>
	/// log the string to the file and print it on the console for debugging
	/// </summary>
	/// <param name="str">- the string to log</param>
	static void log(std::string str);
	/// <summary>
	/// free the deugger and release the log file
	/// </summary>
	static void free();
private:
	/// <summary>
	/// 
	/// </summary>
	static std::ofstream m_file;
};
