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


static std::atomic<bool> done(false);

void free() {
	done = true;
	Logger::free();
	Capture::free();
}

void init() {
	atexit(free);
	Logger::init();
	Capture::init();
	SDK::init();
}

//void callback(pcap_pkthdr* header, const u_char* pkt_data) {
//	auto p = fromRaw(header, pkt_data);
//
//	// std::cout << p->toString();
//}

struct baseP {
	u_char phyDst[6];
	u_char phySrc[6];
	short type;
};

struct caseP : public baseP{
	long l;
	u_char chars[6];
};

class Renderer {
public:
	static void render(baseP v) {
		std::cout << "rendering A packet" << std::endl;
	}
	static void render(caseP v) {
		std::cout << "rendering B packet" << std::endl;
	}
};

template <typename T>
class P {
public:
	T data;

	P(const u_char* pkt_data) {
		std::memcpy(&data, pkt_data, sizeof(T));
	}

	void render() {
		Renderer::render(data);
	}
};

void sampleCallback(pcap_pkthdr* header, const u_char* pkt_data, std::string filename) {
	auto p = fromRaw(header, pkt_data);

	/*std::size_t pos = filename.find('.');
	if (pos != std::string::npos) {
		filename.erase(pos);
	}*/

	/*std::ofstream file(filename + ".txt", std::ios_base::app);

	if (!file) {
		std::cerr << "Error opening file: " << filename + ".txt" << '\n';
		exit(69);
	}

	file << p->jsonify().dump(4) << "\n";*/

	// std::cout << p->jsonify().dump(4) << std::endl;
}

void countPackets(std::vector<int>* counts, int adapterIdx) {
	auto d = Capture::getDev(adapterIdx);
	auto adhandle = Capture::createAdapter(adapterIdx, true);
	struct pcap_pkthdr* header;
	const u_char* pkt_data;
	int r;

	while ((r = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
		if (done) {
			break;
		}
		if (r == 0) {
			continue;
		}

		counts->at(adapterIdx) += 1;
	}

	pcap_close(adhandle);
}


int itsDearingTime() {
	GLFWwindow* window;

	if (!glfwInit())
		return -1;

	window = glfwCreateWindow(640, 480, "Hello World", NULL, NULL);
	if (!window)
	{
		glfwTerminate();
		return -1;
	}

	glfwMakeContextCurrent(window);

	// Initialize Dear ImGui
	IMGUI_CHECKVERSION();
	ImGui::CreateContext();
	ImGuiIO& io = ImGui::GetIO(); (void)io;

	// Set Dear ImGui style
	ImGui::StyleColorsDark();

	// Initialize Dear ImGui backends
	ImGui_ImplGlfw_InitForOpenGL(window, true);
	ImGui_ImplOpenGL3_Init("#version 150");

	while (!glfwWindowShouldClose(window))
	{
		// Poll and handle events
		glfwPollEvents();

		// Start the Dear ImGui frame
		ImGui_ImplOpenGL3_NewFrame();
		ImGui_ImplGlfw_NewFrame();
		ImGui::NewFrame();

		// Create a simple user interface
		{
			static float f = 0.0f;
			static int counter = 0;

			ImGui::Begin("Hello, world!");

			ImGui::Text("This is some useful text.");
			ImGui::SliderFloat("float", &f, 0.0f, 1.0f);
			if (ImGui::Button("Button"))
				counter++;
			ImGui::SameLine();
			ImGui::Text("counter = %d", counter);

			ImGui::End();
		}

		// Rendering
		glClear(GL_COLOR_BUFFER_BIT);
		ImGui::Render();
		ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
		glfwSwapBuffers(window);
	}

	// Cleanup
	ImGui_ImplOpenGL3_Shutdown();
	ImGui_ImplGlfw_Shutdown();
	ImGui::DestroyContext();

	glfwTerminate();
	return 0;
}

#include <type_traits>
#include <cstdint>
#include <bitset>

#include <iostream>
#include <type_traits>
#include <string>



int main(int argc, char* argv[])
{
	std::cout << "fuck" << std::endl;
	//UINT16 chars[] {47, 51, 33, 21};
	//A a;
	//std::memcpy(&a, chars, sizeof(A));
	//std::cout << std::bitset<16>(47) << " + " << std::bitset<16>(51) << " = " << std::bitset<32>(a.a) << std::endl;
	//std::cout << std::bitset<16>(33) << " + " << std::bitset<16>(21) << " = " << std::bitset<32>(a.b) << std::endl;
	//return 0;
	init();

	//return itsDearingTime();
	//
	//if (argc > 1) {
	//	std::string arg = argv[1];

	//	if (arg == "curl") {
	//		std::string addr;
	//		std::cout << "enter the address to geo locate: ";
	//		std::cin >> addr;
	//		std::string cmd = R"(curl -s -H "User-Agent: keycdn-tools:https://amalb.iscool.co.il/" "https://tools.keycdn.com/geo.json?host=")";
	//		cmd += addr;
	//		auto res = SDK::exec(cmd.c_str());
	//		auto j = json::parse(res);
	//		std::cout << j.dump(4);
	//	}
	//	else if (arg == "gui") {
	//		return itsDearingTime();
	//	}

	//	return 0;
	//}	
	//
	//remove("captures/output.pcap");
	//remove("captures/output.txt");

	//std::cout << "hold on. rates are being captured.\n";

	//int constexpr seconds = 1;

	//auto names = Capture::getDeviceNames();

	//auto counts = std::vector<int>(names->size(), 0);

	//auto threads = std::vector<std::thread*>();

	//for (int i = 0; i < names->size(); i++) {
	//	threads.push_back(new std::thread(countPackets, &counts, i));
	//}

	//std::this_thread::sleep_for(std::chrono::seconds(seconds));
	//done = true;

	//std::for_each(threads.cbegin(), threads.cend(), [](std::thread* t) {t->join(); });

	//std::cout << "the following adapters were detected:\n";

	/*for (int i = 0; i < names->size(); i++) {
		std::cout << i + 1 << ". " << names->at(i) << "(packets rate: " << ((float)counts.at(i) / (float)seconds) << " per second)\n";
	}*/

	//int adapterIdx = 0;

	//std::cout << "Enter the number of the adapter you wish to use: ";

	//std::cin >> adapterIdx;

	//if (adapterIdx <= 0 || adapterIdx > names->size()) {
	//	std::cout << "\nnah man that's a bad adapter index\nbetter luck next time\n";
	//	return 0;
	//}

	//// we need it zero indexed
	//adapterIdx -= 1;

	//std::cout << "\nDo you want to enable promiscuous mode? (Y/N): ";

	//std::string temp;

	//std::cin >> temp;

	//bool promiscuous = temp == "Y";

	//std::cout << "\nHow Many packets do you want to capture: ";

	//int maxPackets;

	//std::cin >> maxPackets;

	//if (maxPackets <= 0) {
	//	std::cout << "\nno\n";
	//	return 0;
	//}

	//std::cout << "\nwould you like to apply a filter? if so enter it if not enter X: ";

	//std::string filter;

	//std::cin >> filter;

	//if (filter == "X") {
	//	filter = "";
	//}

	//Capture::sample(adapterIdx, sampleCallback, promiscuous, maxPackets, filter);

	Capture::sample(3, sampleCallback, true, 8, "tcp");

	return 0;
}