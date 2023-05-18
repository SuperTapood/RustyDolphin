#pragma once


class App {
public:
	static void init();
	static void release();
	static void adapterScreen();
	static void captureScreen();

private:
	static void handleStop();
	static void handleStart();
	static void handleStartFile();
	static void getAdapter();
	static void render();
};