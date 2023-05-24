#include "App.h"
#include <Windows.h>

void main()
{
	App::init();

	App::adapterScreen();

	App::captureScreen();
}

#ifdef NDEBUG

// this entry point is needed to compile the program into a command promptless executable
// because nothing can ever be simple in this operating system
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	main();
	return 0;
}

#endif