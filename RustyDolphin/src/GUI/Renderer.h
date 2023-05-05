#pragma once

#include "GUI.h"

#include "../Networks/Packets/Types/Types.h"


class Renderer {
public:
	static void render(Packet* p);
};