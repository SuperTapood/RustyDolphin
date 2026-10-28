#pragma once

#include <expected>
#include <map>
#include <string>
#include <string_view>

namespace core {
using FilterMap = std::map<std::string, std::string>;
std::expected<FilterMap, std::string> parseFilter(std::string_view text);
}
