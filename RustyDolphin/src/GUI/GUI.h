#pragma once

#define IMGUI_USE_STB_SPRINTF

#include <GLFW/glfw3.h>
#include <imgui.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>
#include <map>
#include <string>
#include <pcap.h>

class GUI {
public:
	static GLFWwindow* window;
	static GLuint earthTex;

	static void init();
	static void release();
	static void pushFont(std::string name);
	static void popFont();
	static void centerText(const char* text);
	static bool centerButton(const char* text);
	static void startFrame();
	static void endFrame();

private:
	static std::map<std::string, ImFont*> fonts;
};