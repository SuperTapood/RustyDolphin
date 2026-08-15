#include "App.h"
#include <Windows.h>

int main()
{
	App::init();

	App::adapterScreen();

	App::captureScreen();
	return 0;
}

#ifdef NDEBUG

// this entry point is needed to compile the program into a command promptless executable
// because nothing can ever be simple in this operating system
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	return main();
}

#endif
