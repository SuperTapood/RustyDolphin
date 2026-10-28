#include "App.h"
#include <Windows.h>
#include <exception>
#include <iostream>

namespace {
class ApplicationLifetime {
public:
	ApplicationLifetime() { App::init(); }
	~ApplicationLifetime() { App::release(); }
	ApplicationLifetime(const ApplicationLifetime&) = delete;
	ApplicationLifetime& operator=(const ApplicationLifetime&) = delete;
};
}

int main()
{
	try {
		ApplicationLifetime application;
		App::adapterScreen();
		App::captureScreen();
		return 0;
	}
	catch (const std::exception& error) {
		std::cerr << "RustyDolphin failed: " << error.what() << '\n';
		return 1;
	}
}

#ifdef NDEBUG

// this entry point is needed to compile the program into a command promptless executable
// because nothing can ever be simple in this operating system
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int)
{
	return main();
}

#endif
