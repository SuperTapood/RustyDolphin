#include <iostream>
#include <cstdio>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <thread>
#include "Base/Base.h"
#include "Networks/Networks.h"
#include "GUI/GUI.h"

void release() {
	Data::doneCounting = true;
	Data::doneCapturing = true;
	Logger::release();
	Capture::release();
	SDK::release();
	GUI::release();
}

void init() {
	atexit(release);
	Data::init();
	Logger::init();
	Capture::init();
	SDK::init();
	GUI::init();
}

int main()
{
	init();

	Data::chosenAdapter = GUI::getAdapter();

	if (Data::chosenAdapter == nullptr) {
		return 0;
	}

	Data::captureThread = std::thread(Capture::capturePackets);

	remove("captures/output.pcap");
	remove("captures/output.txt");
	remove("imgui.ini");

	constexpr auto packets = 200;

	GUI::render();	

	Data::doneCapturing = true;
	Data::captureThread.join();

	pcap_close(Data::chosenAdapter);

	return 0;
}

#ifdef NDEBUG

// because nothing can ever be simple in this goddamn operating system
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	return main();
}

#endif