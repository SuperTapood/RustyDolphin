#pragma once

#include <optional>
#include <string>

// Validated data passed from the network worker to the UI. Keeping JSON out of
// the renderer prevents API schema changes from becoming UI exceptions.
struct GeoLocation {
	std::string ip;
	std::string reverseDns;
	std::string isp;
	std::string timezone;
	std::optional<double> latitude;
	std::optional<double> longitude;
};
