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
	static void renderCaptureMenuBar();
	static void renderTable();
	static void renderExpandedPacket();
	static void handleSaveGoing();
	static void handleSave();
	static void handleLoadCapture();
	static void handleLoad();
	static void renderAdapterMenuBar();
	static void renderFilterBox();
	static void alertFilter();
};