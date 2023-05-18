#include "App.h"

void main()
{
	App::init();

	App::adapterScreen();

	App::captureScreen();
}

#ifdef NDEBUG

// because nothing can ever be simple in this goddamn operating system
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	return main();
}

#endif