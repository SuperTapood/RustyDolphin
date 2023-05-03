#pragma once

#include <GLFW/glfw3.h>
#include <imgui.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>


class GUI {
public:
	static GLFWwindow* window;

	static void init();
	static void release();
};