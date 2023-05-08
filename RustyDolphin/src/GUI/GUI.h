#pragma once

#include <GLFW/glfw3.h>
#include <imgui.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>
#include <map>
#include <string>

class GUI {
public:
	static GLFWwindow* window;

	static void init();
	static void release();
	static void pushFont(std::string name);
	static void popFont();
	static void centerText(const char* text);
	static bool centerButton(const char* text);

private:
	static std::map<std::string, ImFont*> fonts;
};