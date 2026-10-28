#include "FilterParser.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <sstream>

namespace core {
namespace {
constexpr std::array keys{ "ip", "sport", "dport", "saddr", "daddr", "proto", "num", "len", "proc" };

std::string trimAndLower(std::string value) {
	const auto first = value.find_first_not_of(' ');
	if (first == std::string::npos) return {};
	value = value.substr(first, value.find_last_not_of(' ') - first + 1);
	std::ranges::transform(value, value.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
	return value;
}
}

std::expected<FilterMap, std::string> parseFilter(std::string_view text) {
	FilterMap result;
	for (const auto* key : keys) result[key] = "";
	if (text.empty()) return result;

	std::stringstream stream{ std::string(text) };
	std::string expression;
	while (std::getline(stream, expression, ',')) {
		const auto equals = expression.find('=');
		if (equals == std::string::npos || equals != expression.rfind('='))
			return std::unexpected(expression + " is not a valid filter");
		auto key = trimAndLower(expression.substr(0, equals));
		auto value = trimAndLower(expression.substr(equals + 1));
		if (key.empty()) return std::unexpected(expression + " has an empty filter name");
		if (value.empty()) return std::unexpected(expression + " has an empty filter value");
		if (std::ranges::find(keys, key) == keys.end()) return std::unexpected("'" + key + "' isn't a valid filter flag.");
		result[key] = value;
	}
	return result;
}
} // namespace core
