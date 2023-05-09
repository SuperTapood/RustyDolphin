#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define STB_IMAGE_WRITE_IMPLEMENTATION
#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <cstdio>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <Winsock2.h>
#include <Windows.h>
#include "Base/Base.h"
#include "Networks/Networks.h"
#include "Win/Win.h"
#include <cstdint>
#include <thread>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <GLFW/glfw3.h>
#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include <fstream>
#include <string>
#include <IcmpAPI.h>
#include <GLFW/glfw3native.h>
#include "GUI/GUI.h"
#include "ImGuiFileDialog.h"
#include <stb_image_write.h>
#include <windows.h>
#include <stdlib.h>
#include <shellapi.h>

void release() {
	Data::doneCounting = true;
	Logger::release();
	Capture::release();
	SDK::release();
	GUI::release();
}

void init() {
	atexit(release);
	Logger::init();
	Capture::init();
	SDK::init();
	GUI::init();
}

void countPackets(std::vector<int>* counts, int adapterIdx) {
	auto d = Capture::getDev(adapterIdx);
	auto adhandle = Capture::createAdapter(adapterIdx, true);
	struct pcap_pkthdr* header;
	const u_char* pkt_data;
	int r;

	while ((r = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
		if (Data::doneCounting) {
			break;
		}
		if (r == 0) {
			continue;
		}

		counts->at(adapterIdx) += 1;
	}

	pcap_close(adhandle);
}

void callback(pcap_pkthdr* header, const u_char* pkt_data, std::string filename, unsigned int idx) {
	auto p = fromRaw(header, pkt_data, idx);

	//if (idx == 982) {
	//	p = fromRaw(header, pkt_data, idx);
	//	std::size_t pos = filename.find('.');
	//	if (pos != std::string::npos) {
	//		filename.erase(pos);
	//	}

	//	std::ofstream file(filename + ".txt", std::ios_base::app);

	//	if (!file) {
	//		std::cerr << "Error opening file: " << filename + ".txt" << '\n';
	//		exit(69);
	//	}

	//	file << p->jsonify().dump(4) << "\n";

	//	 std::cout << p->jsonify().dump(4) << std::endl;

	//	 std::cout << p->toString() << std::endl;
	//	/*std::cout << "hey:" << std::endl;
	//	for (int i = 0; i < p->m_len; i++) {
	//		std::cout << std::hex << (int)p->m_pktData[i];
	//	}*/
	//}

	Data::addPacket(p);
}

std::pair<pcap_t*, bool> getAdapter() {
#ifdef _DEBUG
	return { Capture::createAdapter(3), true };
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
		threads.push_back(new std::thread(countPackets, &counts, i));
	}

	srand(time(NULL));

	int randomNumber = rand() % Data::quotes.size();

	std::vector<float> rates;

	rates.assign(names.size(), 0.0f);

	int last = 0;
	int selected = -1;
	bool promiscous = false;

	while (!Data::doneCounting) {
		// Poll and handle events
		glfwPollEvents();

		// Start the Dear ImGui frame
		ImGui_ImplOpenGL3_NewFrame();
		ImGui_ImplGlfw_NewFrame();
		ImGui::NewFrame();

		if (glfwWindowShouldClose(GUI::window)) {
			exit(0);
		}

		ImGui::SetNextWindowPos(ImVec2(0, 0));
		ImGui::SetNextWindowSize(ImVec2(1280, 720));
		ImGui::Begin("Adapter Selection Window", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar);

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
				if (GUI::centerButton("Yes, in Promiscous Mode")) {
					Data::doneCounting = true;
					promiscous = true;
					GUI::popFont();
					ImGui::EndPopup();
					ImGui::End();

					// auto io = ImGui::GetIO();

					// std::cout << io.Framerate << " FPS\n";

					glClear(GL_COLOR_BUFFER_BIT);
					ImGui::Render();
					ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
					glfwSwapBuffers(GUI::window);
					break;
				}
				if (GUI::centerButton("Yes, not in Promiscous Mode")) {
					Data::doneCounting = true;
					GUI::popFont();
					ImGui::EndPopup();
					ImGui::End();

					// auto io = ImGui::GetIO();

					// std::cout << io.Framerate << " FPS\n";

					glClear(GL_COLOR_BUFFER_BIT);
					ImGui::Render();
					ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
					glfwSwapBuffers(GUI::window);
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

		glClear(GL_COLOR_BUFFER_BIT);
		ImGui::Render();
		ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
		glfwSwapBuffers(GUI::window);
	}

	std::for_each(threads.cbegin(), threads.cend(), [](std::thread* t) {t->join(); });

	SDK::findIP(Capture::getDev(selected)->name);

	return { Capture::createAdapter(selected), promiscous };
}

int main(int argc, char* argv[])
{
	init();

	auto [adapter, prom] = getAdapter();

	remove("captures/output.pcap");
	remove("captures/output.txt");
	remove("imgui.ini");

	constexpr auto packets = 5;
	constexpr auto columns = 7;

	Capture::capturePackets(adapter, callback, prom, packets);

	int selected = -1;

	while (!glfwWindowShouldClose(GUI::window))
	{
		// Poll and handle events
		glfwPollEvents();

		// Start the Dear ImGui frame
		ImGui_ImplOpenGL3_NewFrame();
		ImGui_ImplGlfw_NewFrame();
		ImGui::NewFrame();

		GUI::pushFont("regular");

		ImGui::SetNextWindowPos(ImVec2(0, 0));
		ImGui::SetNextWindowSize(ImVec2(1280, 360));
		ImGui::Begin("Packet Table Window", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar);

		if (ImGui::BeginTable("Packet Table", columns))
		{
			ImGui::TableSetupColumn("No.", ImGuiTableColumnFlags_WidthFixed, 80.0f);
			ImGui::TableSetupColumn("Time", ImGuiTableColumnFlags_WidthFixed, 90.0f);
			ImGui::TableSetupColumn("Source", ImGuiTableColumnFlags_WidthFixed, 170.0f);
			ImGui::TableSetupColumn("Destination", ImGuiTableColumnFlags_WidthFixed, 170.0f);
			ImGui::TableSetupColumn("Protocol", ImGuiTableColumnFlags_WidthFixed, 100.0f);
			ImGui::TableSetupColumn("Length", ImGuiTableColumnFlags_WidthFixed, 50.0f);
			ImGui::TableSetupColumn("Info", ImGuiTableColumnFlags_WidthFixed, 620.0f);
			ImGui::TableHeadersRow();

			for (int row = 0; row < packets; row++)
			{
				ImGui::TableNextRow();
				Data::captured.at(row)->render();
			}
			ImGui::EndTable();
		}
		ImGui::End();

		if (Data::selected != -1) {
			ImGui::SetNextWindowPos(ImVec2(0, 360));
			ImGui::SetNextWindowSize(ImVec2(640, 360));
			ImGui::Begin("Expanded Packet", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar);

			Data::captured.at(Data::selected)->renderExpanded();

			ImGui::End();

			ImGui::SetNextWindowPos(ImVec2(640, 360));
			ImGui::SetNextWindowSize(ImVec2(640, 360));
			ImGui::Begin("Packet Data View", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar);

			std::string str;

			GUI::pushFont("hexView");

			auto p = Data::captured.at(Data::selected);

			int inc = 0;

			for (int i = 0; i < p->m_hexData.size(); i+=2) {
				std::string byte = p->m_hexData.substr(i, 2);
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

			//ImGui::Text(Data::captured.at(Data::selected)->m_hexData.c_str());

			ImGui::End();
		}

		// Rendering
		GUI::popFont();
		glClear(GL_COLOR_BUFFER_BIT);
		ImGui::Render();
		ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
		glfwSwapBuffers(GUI::window);
	}

	return 0;
}

#ifdef NDEBUG

// because nothing can ever be simple in this fcking operating system
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	int argc;
	LPWSTR* argvW = CommandLineToArgvW(GetCommandLineW(), &argc);
	char** argv = new char* [argc];
	for (int i = 0; i < argc; ++i) {
		int wlen = lstrlenW(argvW[i]);
		int size = WideCharToMultiByte(CP_ACP, 0, argvW[i], wlen, NULL, 0, NULL, NULL);
		argv[i] = new char[size + 1];
		WideCharToMultiByte(CP_ACP, 0, argvW[i], wlen, argv[i], size + 1, NULL, NULL);
	}
	LocalFree(argvW);

	int result = main(argc, argv);

	for (int i = 0; i < argc; ++i) {
		delete[] argv[i];
	}
	delete[] argv;

	return result;
}

#endif