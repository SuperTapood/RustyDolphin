#include "App.h"

#include <stdlib.h>

#include "Base/Data.h"
#include "Base/MacroSettings.h"
#include "GUI/GUI.h"
#include "Base/Logger.h"
#include "Networks/capture.h"
#include "Win/SDK.h"
#include "ImGuiFileDialog.h"
#include <iostream>

void App::release() {
	Data::doneCounting = true;
	Data::doneCapturing = true;
	Data::geoTerminate = true;
	Logger::release();
	Capture::release();
	SDK::release();
	GUI::release();
	if (Data::chosenAdapter != nullptr) {
		pcap_close(Data::chosenAdapter);
	}
}

void App::init() {
	remove("captures/output.pcap");
	remove("captures/output.txt");
	remove("imgui.ini");
	atexit(App::release);
	Data::init();
	Logger::init();
	Capture::init();
	SDK::init();
	GUI::init();
}

void App::adapterScreen() {
	getAdapter();

	if (Data::chosenAdapter == nullptr) {
		exit(-1);
	}
}

void App::captureScreen() {
	Data::captureThread = std::jthread(Capture::capturePackets);

	render();

	Data::doneCapturing = true;
	Data::captureThread.join();
}

void App::renderAdapterMenuBar() {
	GUI::pushFont("regular");
	if (ImGui::BeginMainMenuBar()) {
		if (ImGui::BeginMenu("File")) {
			if (ImGui::MenuItem("Load")) {
				Data::showLoad = true;
			}
			ImGui::EndMenu();
		}
		ImGui::EndMainMenuBar();
	}
	GUI::popFont();
}

void App::handleLoad() {
	ImGui::SetNextWindowPos(ImVec2(100, 100));
	ImGui::SetNextWindowSize(ImVec2(1080, 480));
	// open Dialog Simple
	ImGuiFileDialog::Instance()->OpenDialog("ChooseFileDlgKey", "Choose File", ".pcapng,.pcap,", ".");

	// display
	if (ImGuiFileDialog::Instance()->Display("ChooseFileDlgKey"))
	{
		// action if OK
		if (ImGuiFileDialog::Instance()->IsOk())
		{
			std::string filePathName = ImGuiFileDialog::Instance()->GetFilePathName();
			std::string filePath = ImGuiFileDialog::Instance()->GetCurrentPath();

			Data::fileAdapter = true;
			Data::chosenAdapter = Capture::load(filePathName);
			Data::doneCounting = true;
			Data::showLoad = false;
		}
		else {
			Data::showLoad = false;
		}

		// close
		ImGuiFileDialog::Instance()->Close();
	}
}

void App::getAdapter() {
#ifdef CAPTURE_LIVE
	Data::fileAdapter = false;
	Data::chosenAdapter = Capture::createAdapter(3);
	SDK::findIP(Capture::getDev(3)->name);
	return;
#endif
#ifdef CAPTURE_SAMPLES
	Data::fileAdapter = true;
	Data::chosenAdapter = Capture::load("samples.pcapng");
	return;
#endif
#ifdef CAPTURE_V6
	Data::fileAdapter = true;
	Data::chosenAdapter = Capture::load("v6.pcapng");
	return;
#endif
#ifdef CAPTURE_ICMPV6
	Data::fileAdapter = true;
	Data::chosenAdapter = Capture::load("icmpv6.pcapng");
	return;
#endif
	using std::chrono::high_resolution_clock;
	using std::chrono::duration_cast;
	using std::chrono::duration;
	using std::chrono::milliseconds;

	auto names = Capture::getDeviceNames();

	auto counts = std::vector<int>(names.size(), 0);

	auto threads = std::vector<std::thread*>();

	auto t1 = high_resolution_clock::now();

	for (int i = 0; i < names.size(); i++) {
		threads.push_back(new std::thread(Capture::countPackets, &counts, i));
	}

	srand(time(NULL));

	int randomNumber = rand() % Data::quotes.size();

	std::vector<float> rates;

	rates.assign(names.size(), 0.0f);

	int last = 0;
	int selected = -1;

	while (!Data::doneCounting) {
		GUI::startFrame();

		if (glfwWindowShouldClose(GUI::window)) {
			exit(0);
		}

		ImGui::SetNextWindowPos(ImVec2(0, 20));
		ImGui::SetNextWindowSize(ImVec2(1280, 700));
		ImGui::Begin("Adapter Selection Window", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar);

		renderAdapterMenuBar();

		if (Data::showLoad) {
			GUI::pushFont("regular");
			handleLoad();
			GUI::popFont();
		}

		ImGui::SetCursorPos(ImVec2(340, 0));
		GUI::pushFont("title");
		GUI::centerText("Welcome to RustyDolphin");
		GUI::popFont();

		GUI::pushFont("quote");
		GUI::centerText(Data::quotes.at(randomNumber));
		GUI::popFont();

		GUI::pushFont("adapters");
		ImGui::SetCursorPosY(150);
		ImGui::Text("Choose the adapter you'd like to use:");

		auto t2 = high_resolution_clock::now();
		auto ms_int = duration_cast<milliseconds>(t2 - t1);
		auto secs = (double)ms_int.count() / 1000;

		if (secs >= ((double)last / 5.0)) {
			for (int i = 0; i < rates.size(); i++) {
				rates.at(i) = ((float)counts.at(i) / secs);
			}
			last++;
		}

		std::stringstream ss;
		for (int i = 0; i < names.size(); i++) {
			ImGui::SetCursorPosX(150);
			ss << names.at(i) << " (Packet Rate: " << rates.at(i) << " per second)";
			if (ImGui::Button(ss.str().c_str())) {
				selected = i;
			}
			ss.str("");
		}

		if (selected != -1) {
			ImGui::OpenPopup("AdapterSelectPopup");

			ImGui::SetNextWindowSize(ImVec2(600, 500));
			ImGui::SetNextWindowPos(ImVec2(640 - 300, 360 - 250));
			if (ImGui::BeginPopupModal("AdapterSelectPopup", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoTitleBar))
			{
				GUI::centerText("Are you sure you want this adapter?");
				ImGui::SetCursorPosY(350);
				if (GUI::centerButton("Yes")) {
					Data::doneCounting = true;
					GUI::popFont();
					ImGui::EndPopup();
					ImGui::End();
					GUI::endFrame();
					break;
				}
				ImGui::SetCursorPosY(430);
				if (GUI::centerButton("No")) {
					selected = -1;
					ImGui::CloseCurrentPopup();
				}
				ImGui::EndPopup();
			}
		}

		GUI::popFont();

		ImGui::End();

		GUI::endFrame();
	}

	std::ranges::for_each(threads.cbegin(), threads.cend(), [](std::thread* t) {t->join(); });

	Data::fileAdapter = false;

	if (selected != -1) {
		Data::chosenAdapter = Capture::createAdapter(selected);
	}
	SDK::findIP(Capture::getDev(selected)->name);
}

void App::handleStop() {
	GUI::pushFont("adapters");
	ImGui::OpenPopup("StopCapture");

	ImGui::SetNextWindowSize(ImVec2(600, 500));
	ImGui::SetNextWindowPos(ImVec2(640 - 300, 360 - 250));
	if (ImGui::BeginPopupModal("StopCapture", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoTitleBar))
	{
		GUI::centerText("Are you sure you want stop the current capture?");
		ImGui::SetCursorPosY(350);
		if (GUI::centerButton("Yes")) {
			Data::doneCapturing = true;
			Data::showStop = false;
		}
		ImGui::SetCursorPosY(430);
		if (GUI::centerButton("No")) {
			Data::showStop = false;
		}
		ImGui::EndPopup();
	}
	GUI::popFont();
}

void App::handleStart() {
	GUI::pushFont("adapters");
	ImGui::OpenPopup("StartCapture");

	ImGui::SetNextWindowSize(ImVec2(600, 500));
	ImGui::SetNextWindowPos(ImVec2(340, 110));
	if (ImGui::BeginPopupModal("StartCapture", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoTitleBar))
	{
		GUI::centerText("You have an ongoing capture.");
		GUI::centerText("do you want to start another one?");
		GUI::centerText("(the current one will be reset)");
		ImGui::SetCursorPosY(350);
		if (GUI::centerButton("Yes")) {
			Data::doneCapturing = true;
			Data::selected = -1;
			Data::showStart = false;
			Data::captureThread.join();
			for (auto p : Data::captured) {
				delete p;
			}
			Data::captured.clear();
			Data::capIdx = 0;
			Data::doneCapturing = false;
			Data::captureThread = std::jthread(Capture::capturePackets);
		}
		ImGui::SetCursorPosY(430);
		if (GUI::centerButton("No")) {
			Data::showStart = false;
		}
		ImGui::EndPopup();
	}
	GUI::popFont();
}

void App::handleStartFile() {
	GUI::pushFont("adapters");
	ImGui::OpenPopup("StartCapture");

	ImGui::SetNextWindowSize(ImVec2(600, 500));
	ImGui::SetNextWindowPos(ImVec2(640 - 300, 360 - 250));
	if (ImGui::BeginPopupModal("StartCapture", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoTitleBar))
	{
		GUI::centerText("Your current capture is from a file.");
		GUI::centerText("file captures cannot be re-started.");
		GUI::centerText("would you like to reset the currently captured packets?");
		ImGui::SetCursorPosY(350);
		if (GUI::centerButton("Yes")) {
			Data::doneCapturing = true;
			Data::selected = -1;
			Data::showStart = false;
			Data::captureThread.join();
			for (auto p : Data::captured) {
				delete p;
			}
			Data::captured.clear();
			Data::capIdx = 0;
			Data::doneCapturing = false;
			Data::captureThread = std::jthread(Capture::capturePackets);
		}
		ImGui::SetCursorPosY(430);
		if (GUI::centerButton("No")) {
			Data::showStart = false;
		}
		ImGui::EndPopup();
	}
	GUI::popFont();
}

void App::handleSaveGoing() {
	GUI::pushFont("adapters");
	ImGui::OpenPopup("Save Packets");
	ImGui::SetNextWindowSize(ImVec2(600, 500));
	ImGui::SetNextWindowPos(ImVec2(640 - 300, 360 - 250));
	if (ImGui::BeginPopupModal("Save Packets", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoTitleBar))
	{
		GUI::centerText("Your current capture is still on going.");
		GUI::centerText("Stop the current capture to save.");
		ImGui::SetCursorPosY(350);
		if (GUI::centerButton("OK")) {
			Data::showSave = false;
		}
		ImGui::EndPopup();
	}
	GUI::popFont();
}

void App::handleSave() {
	ImGui::SetNextWindowPos(ImVec2(100, 100));
	ImGui::SetNextWindowSize(ImVec2(1080, 480));
	// open Dialog Simple
	ImGuiFileDialog::Instance()->OpenDialog("ChooseFileDlgKey", "Choose File", ".pcapng,.pcap,", ".", 1, nullptr, ImGuiFileDialogFlags_ConfirmOverwrite);

	// display
	if (ImGuiFileDialog::Instance()->Display("ChooseFileDlgKey"))
	{
		// action if OK
		if (ImGuiFileDialog::Instance()->IsOk())
		{
			std::string filePathName = ImGuiFileDialog::Instance()->GetFilePathName();
			std::string filePath = ImGuiFileDialog::Instance()->GetCurrentPath();

			Capture::dumpAll(filePathName);

			Data::showSave = false;
		}
		else {
			Data::showSave = false;
		}

		// close
		ImGuiFileDialog::Instance()->Close();
	}
}

void App::handleLoadCapture() {
	ImGui::SetNextWindowPos(ImVec2(100, 100));
	ImGui::SetNextWindowSize(ImVec2(1080, 480));
	// open Dialog Simple
	ImGuiFileDialog::Instance()->OpenDialog("ChooseFileDlgKey", "Choose File", ".pcapng,.pcap,", ".");

	// display
	if (ImGuiFileDialog::Instance()->Display("ChooseFileDlgKey"))
	{
		// action if OK
		if (ImGuiFileDialog::Instance()->IsOk())
		{
			std::string filePathName = ImGuiFileDialog::Instance()->GetFilePathName();
			std::string filePath = ImGuiFileDialog::Instance()->GetCurrentPath();

			Data::doneCapturing = true;
			Data::selected = -1;
			Data::showStart = false;
			Data::captureThread.join();
			for (auto p : Data::captured) {
				delete p;
			}
			Data::captured.clear();
			Data::capIdx = 0;
			Data::doneCapturing = false;
			Data::doneLoading = false;
			Data::fileAdapter = true;
			Data::showLoad = false;
			Data::chosenAdapter = Capture::load(filePathName);
			Data::captureThread = std::jthread(Capture::capturePackets);
		}
		else {
			Data::showLoad = false;
		}

		// close
		ImGuiFileDialog::Instance()->Close();
	}
}

void App::filterHelp() {
	GUI::pushFont("adapters");
	ImGui::OpenPopup("Filter Help");
	ImGui::SetNextWindowSize(ImVec2(1080, 520));
	ImGui::SetNextWindowPos(ImVec2(100, 100));
	if (ImGui::BeginPopupModal("Filter Help", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoTitleBar))
	{
		GUI::centerText("Filter Documentation");
		GUI::centerText("below are the allowed filters and the values they accept:");
		ImGui::Text("num");
		GUI::pushFont("regular");
		ImGui::Text("the number of the packet in the packet stream. (this filter only shows one packet)");
		ImGui::Text("for example, if you wanted to only see packet number 68 you can type: 'num=68'");
		GUI::popFont();
		ImGui::Text("len");
		GUI::pushFont("regular");
		ImGui::Text("the overall length of the packet in bytes (bytes on wire)");
		ImGui::Text("for example, if you wanted to only see packets containing exactly 60 bytes you can type: 'len=60'");
		GUI::popFont();
		ImGui::Text("ip");
		GUI::pushFont("regular");
		ImGui::Text("the type of meta-protocol used in the packet itself (called ip for brevity, but this also includes arp)");
		ImGui::Text("for example, if you wanted to only see arp packets you can type: 'ip=arp'");
		GUI::popFont();
		ImGui::Text("proto");
		GUI::pushFont("regular");
		ImGui::Text("the type of protocol used in the packet itself (such as TCP, UDP, ICMP, etc)");
		ImGui::Text("for example, if you wanted to only see packets which use the IGMP protocol you can type: 'proto=igmp'");
		GUI::popFont();
		ImGui::Text("saddr");
		GUI::pushFont("regular");
		ImGui::Text("the address (whether it is IPv4, IPv6, or MAC depends on the packet) of the packet's source");
		ImGui::Text("for example, if you wanted to only see packets which came from 10.0.11.69 you can type: 'saddr=10.0.11.69'");
		GUI::popFont();
		ImGui::Text("daddr");
		GUI::pushFont("regular");
		ImGui::Text("the address (whether it is IPv4, IPv6, or MAC depends on the packet) of the packet's destination");
		ImGui::Text("for example, if you wanted to only see packets which are addressed to MAC broadcast you can type: 'daddr=ff:ff:ff:ff:ff:ff'");
		GUI::popFont();
		ImGui::Text("sport");
		GUI::pushFont("regular");
		ImGui::Text("the port from which the packet originated");
		ImGui::Text("for example, if you wanted to only see packets which came from port 443 you can type: 'sport=443'");
		GUI::popFont();
		ImGui::Text("dport");
		GUI::pushFont("regular");
		ImGui::Text("the port to which the packet is headed");
		ImGui::Text("for example, if you wanted to only see packets headed to port 42069 you can type: 'dport=42069'");
		GUI::popFont();
		ImGui::Text("proc");
		GUI::pushFont("regular");
		ImGui::Text("the process which sent the packet (due to the way the process detecting works, only tcp and udp connections are detected, and some mistakes may be made)");
		ImGui::Text("for example, if you wanted to only see packets sent / received by Google's Chrome you can: 'proc=chrome.exe'");
		GUI::popFont();
		ImGui::Text("notes");
		GUI::pushFont("regular");
		ImGui::Text("-in order to chain multiple filters together, use commas to sepearte them: 'proto=tcp, proc=msedge.exe, len=42'");
		ImGui::Text("-leading and trailing spaces are trimmed from filter inputs to reduce the amount of headache :)");
		ImGui::Text("-if a bad filter is given, no packet will be presented");
		ImGui::Text("-each presented packet has to pass every filter. you cannot use filters to present both tcp and udp packets for example by using");
		ImGui::Text("'proto=tcp, proto=udp'. only udp packets will be presented as its the last filter");
		GUI::popFont();
		ImGui::Text("\n\n");
		if (GUI::centerButton("OK")) {
			Data::showFilterHelp = false;
		}
		ImGui::EndPopup();
	}
	GUI::popFont();
}

void App::renderCaptureMenuBar() {
	if (ImGui::BeginMainMenuBar()) {
		if (ImGui::BeginMenu("File")) {
			if (ImGui::MenuItem("Load")) {
				Data::showLoad = true;
			}
			if (ImGui::MenuItem("Save")) {
				Data::showSave = true;
			}
			ImGui::EndMenu();
		}
		if (ImGui::BeginMenu("Capture")) {
			if (ImGui::MenuItem("Start")) {
				Data::showStart = true;
			}
			if (ImGui::MenuItem("Stop")) {
				Data::showStop = true;
			}
			ImGui::EndMenu();
		}
		if (ImGui::BeginMenu("Help")) {
			if (ImGui::MenuItem("Filter Docs")) {
				Data::showFilterHelp = true;
			}
			ImGui::EndMenu();
		}
		std::string text = std::format("total packet captured: {} | packets displayed: {}", Data::capIdx, Data::displayed);
		ImVec2 textSize = ImGui::CalcTextSize(text.c_str());
		ImGui::SetCursorPosX(ImGui::GetWindowWidth() - textSize.x);
		ImGui::Text(text.c_str());
		ImGui::EndMainMenuBar();
	}
}

constexpr auto columns = 7;

void App::renderTable() {
	if (ImGui::BeginTable("Packet Table", columns, ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg))
	{
		ImGui::TableSetupScrollFreeze(0, 1);
		ImGui::TableSetupColumn(("No."), ImGuiTableColumnFlags_WidthFixed, 80.0f);
		ImGui::TableSetupColumn("Time", ImGuiTableColumnFlags_WidthFixed, 90.0f);
		ImGui::TableSetupColumn("Source", ImGuiTableColumnFlags_WidthFixed, 200.0f);
		ImGui::TableSetupColumn("Destination", ImGuiTableColumnFlags_WidthFixed, 200.0f);
		ImGui::TableSetupColumn("Protocol", ImGuiTableColumnFlags_WidthFixed, 100.0f);
		ImGui::TableSetupColumn("Length", ImGuiTableColumnFlags_WidthFixed, 50.0f);
		ImGui::TableSetupColumn("Info", ImGuiTableColumnFlags_WidthFixed, 560.0f);
		ImGui::TableHeadersRow();

		Data::displayed = 0;

		for (int row = 0; row < Data::capIdx; row++)
		{
			auto p = Data::captured.at(row);
			{
				std::lock_guard<std::mutex> guard(Data::guard);
				Renderer::filterPacket(p);
			}

			if (row == Data::selected)
			{
				ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, ImGui::ColorConvertFloat4ToU32(ImVec4(56.f / 255.f, 123.f / 255.f, 203.f / 255.f, 0.5)));
			}
		}

		// after one frame the filter is no longer new
		Data::newFilter = false;
		ImGui::EndTable();
	}
	ImGui::End();
}

void App::renderExpandedPacket() {
	ImGui::SetNextWindowPos(ImVec2(0, 380));
	ImGui::SetNextWindowSize(ImVec2(780, 340));
	ImGui::Begin("Expanded Packet", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar);

	Data::captured.at(Data::selected)->renderExpanded();

	ImGui::End();

	ImGui::SetNextWindowPos(ImVec2(780, 380));
	ImGui::SetNextWindowSize(ImVec2(500, 340));
	ImGui::Begin("Packet Data View", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar);

	std::string str;

	GUI::pushFont("hexView");

	auto p = Data::captured.at(Data::selected);

	int inc = 0;

	auto hexData = p->getTexts().at("hexData");

	for (int i = 0; i < hexData.size(); i += 2) {
		std::string byte = hexData.substr(i, 2);
		if (i % 32 == 0 && i > 0) {
			std::stringstream ss;
			ss << std::hex << std::setw(4) << std::setfill('0') << inc;
			ImGui::SetCursorPosX(10);
			ImGui::Text((ss.str() + " " + str).c_str());
			str = " " + byte;
			inc += 16;
		}
		else {
			str += " " + byte;
		}
	}
	ImGui::SetCursorPosX(10);
	std::stringstream ss;
	ss << std::hex << std::setw(4) << std::setfill('0') << inc;
	ImGui::Text((ss.str() + " " + str).c_str());

	GUI::popFont();

	ImGui::End();
}

void App::alertFilter() {
	GUI::pushFont("adapters");
	ImGui::OpenPopup("Bad Filter");
	ImGui::SetNextWindowSize(ImVec2(600, 500));
	ImGui::SetNextWindowPos(ImVec2(640 - 300, 360 - 250));
	if (ImGui::BeginPopupModal("Bad Filter", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoTitleBar))
	{
		GUI::centerText("Your filter is not correct:");
		GUI::centerText(Data::filterIssue.c_str());
		GUI::centerText("\nIf you need help with filtering");
		GUI::centerText("You can use the documentation:");
		GUI::centerText("Help->Filter Docs");
		ImGui::SetCursorPosY(350);
		if (GUI::centerButton("OK")) {
			Data::showBadFilter = false;
		}
		ImGui::EndPopup();
	}
	GUI::popFont();
}

void App::renderFilterBox() {
	ImGui::InputText("##", Data::filterTxt, IM_ARRAYSIZE(Data::filterTxt));

	ImGui::SameLine();

	if (ImGui::Button("Apply")) {
		Data::processFilter();
	}

	ImGui::SameLine();

	if (ImGui::Button("Clear")) {
		Data::filterTxt[0] = '\0';
	}

	if (Data::showBadFilter) {
		alertFilter();
	}
}

void App::geoTable() {
	if (ImGui::BeginTable("Geo Table", columns, ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg, ImVec2(1250, 500)))
	{
		GUI::pushFont("regular");
		ImGui::TableSetupScrollFreeze(0, 1);
		ImGui::TableSetupColumn("Hop Number", ImGuiTableColumnFlags_WidthFixed, 90.0f);
		ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 120.0f);
		ImGui::TableSetupColumn("reverse DNS", ImGuiTableColumnFlags_WidthFixed, 320.0f);
		ImGui::TableSetupColumn("ISP", ImGuiTableColumnFlags_WidthFixed, 300.0f);
		ImGui::TableSetupColumn("Latitude", ImGuiTableColumnFlags_WidthFixed, 110.0f);
		ImGui::TableSetupColumn("Longitude", ImGuiTableColumnFlags_WidthFixed, 110.0f);
		ImGui::TableSetupColumn("Timezone", ImGuiTableColumnFlags_WidthFixed, 180.0f);
		ImGui::TableHeadersRow();

		for (int row = 0; row < Data::locs.size(); row++) {
			ImGui::TableNextRow();
			auto j = Data::locs.at(row);

			{
				auto data = j.at("data").at("geo");
				std::lock_guard<std::mutex> guard(Data::geoGuard);
				ImGui::TableSetColumnIndex(0);
				ImGui::Text(std::to_string(row).c_str());
				ImGui::TableSetColumnIndex(1);
				ImGui::Text(data.at("ip").dump(0).c_str());
				ImGui::TableSetColumnIndex(2);
				ImGui::Text(data.at("rdns").dump(0).c_str());
				ImGui::TableSetColumnIndex(3);
				ImGui::Text(data.at("isp").dump(0).c_str());
				ImGui::TableSetColumnIndex(4);
				ImGui::Text(data.at("latitude").dump(0).c_str());
				ImGui::TableSetColumnIndex(5);
				ImGui::Text(data.at("longitude").dump(0).c_str());
				ImGui::TableSetColumnIndex(6);
				ImGui::Text(data.at("timezone").dump(0).c_str());
			}
		}

		GUI::popFont();
		ImGui::EndTable();
	}
}

void App::showHops() {
	ImVec2 window_size = ImGui::GetContentRegionAvail();
	auto xShift = (window_size.x - 1024) * 0.5f;
	ImGui::SetCursorPosX(xShift);
	ImGui::Image((void*)(intptr_t)GUI::earthTex, ImVec2(1024, 794));
	std::pair<double, double> lastCoords = { -1, -1 };
	ImDrawList* draw_list = ImGui::GetWindowDrawList();
	constexpr auto r = 4;
	for (int row = 0; row < Data::locs.size(); row++) {
		auto j = Data::locs.at(row);
		double longitude;
		double latitude;
		{
			auto data = j.at("data").at("geo");
			std::lock_guard<std::mutex> guard(Data::geoGuard);
			auto longS = data.at("longitude").dump(0);
			if (longS == "\"\"" || longS == "null") {
				continue;
			}
			longitude = std::stod(longS);
			auto latS = data.at("latitude").dump(0);
			if (latS == "\"\"" || latS == "null") {
				continue;
			}
			latitude = std::stod(latS);
		}
		auto [x, y] = Data::mercatorProjection(longitude, latitude);

		ImVec2 cursor_pos = ImGui::GetCursorScreenPos();
		ImVec2 circle_pos = ImVec2(cursor_pos.x + xShift + x - r, cursor_pos.y + y - 794 - r);
		draw_list->AddCircleFilled(circle_pos, r, IM_COL32(255, 0, 0, 255));

		if (lastCoords.first != -1) {
			draw_list->AddLine(ImVec2(lastCoords.first, lastCoords.second), circle_pos, IM_COL32(255, 0, 0, 255), r / 2);
		}

		lastCoords.first = circle_pos.x;
		lastCoords.second = circle_pos.y;
	}
}

void App::showGeoTrace() {
	GUI::pushFont("adapters");
	ImGui::OpenPopup("GeoLoc");
	ImGui::SetNextWindowSize(ImVec2(1280, 720));
	ImGui::SetNextWindowPos(ImVec2(0, 0));
	if (ImGui::BeginPopupModal("GeoLoc", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoTitleBar))
	{
		GUI::centerText(std::format("Hopping Map for address {}", Data::hopAddr).c_str());
		if (Data::geoState == 1) {
			GUI::centerText("Querying Address...");
		}
		else if (Data::geoState == 2) {
			GUI::centerText("Processing Replies...");
		}
		else if (Data::geoState == 3) {
			GUI::centerText("No address could be reached :(");
		}
		else if (Data::geoState == 4) {
			GUI::centerText("Processing Done");
		}
		geoTable();
		showHops();
		if (GUI::centerButton("OK")) {
			if (!Data::geoDone) {
				Data::geoAlert = true;
			}
			else {
				Data::geoLocThread.join();
				Data::showGeoTrace = -1;
				Data::locs.clear();
			}
		}

		if (Data::geoAlert) {
			ImGui::OpenPopup("hotshot");
			ImGui::SetNextWindowSize(ImVec2(600, 500));
			ImGui::SetNextWindowPos(ImVec2(640 - 300, 360 - 250));
			if (ImGui::BeginPopupModal("hotshot", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoTitleBar))
			{
				GUI::centerText("you cannot exit just yet");
				GUI::centerText("the data caputring is not yet done\n");
				ImGui::SetCursorPosY(350);
				if (GUI::centerButton("OK")) {
					Data::geoAlert = false;
				}
				ImGui::EndPopup();
			}
		}
	}
	ImGui::End();
	GUI::popFont();
}

void App::render() {
	const auto upArrow = ImGui::GetKeyIndex(ImGuiKey_UpArrow);
	const auto downArrow = ImGui::GetKeyIndex(ImGuiKey_DownArrow);
	while (!glfwWindowShouldClose(GUI::window))
	{
		GUI::startFrame();

		GUI::pushFont("regular");

		ImGui::SetNextWindowPos(ImVec2(0, 20));
		ImGui::SetNextWindowSize(ImVec2(1280, 360));
		ImGui::Begin("Packet Table Window", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar);

		renderCaptureMenuBar();

		renderFilterBox();

		renderTable();

		if (Data::showFilterHelp) {
			filterHelp();
		}

		if (Data::selected != -1) {
			renderExpandedPacket();
		}

		if (Data::showStop) {
			handleStop();
		}
		else if (Data::showStart && !Data::fileAdapter) {
			handleStart();
		}
		else if (Data::showStart && Data::fileAdapter) {
			handleStartFile();
		}

		else if (!Data::doneCapturing && Data::showSave) {
			handleSaveGoing();
		}
		else if (Data::doneCapturing && Data::showSave) {
			handleSave();
		}

		else if (Data::showLoad) {
			handleLoadCapture();
		}

		else if (Data::showGeoTrace != -1) {
			showGeoTrace();
		}

		GUI::popFont();

		if (ImGui::IsKeyPressed(upArrow)) {
			Data::selected = max(Data::selected - 1, 0);
		}

		if (ImGui::IsKeyPressed(downArrow)) {
			Data::selected = min(Data::selected + 1, Data::capIdx);
		}

		GUI::endFrame();
	}
}