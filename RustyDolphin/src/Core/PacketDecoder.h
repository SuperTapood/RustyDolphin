#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>

namespace core {

struct ParseError {
	std::size_t offset{};
	std::string message;
};

template <typename T>
using ParseResult = std::expected<T, ParseError>;

struct EthernetHeader {
	std::uint16_t etherType{};
};

struct IPv4Header {
	std::uint8_t version{};
	std::uint8_t headerLength{};
	std::uint16_t totalLength{};
	std::uint16_t fragmentOffset{};
	std::uint8_t protocol{};
};

struct IPv6Header {
	std::uint8_t version{};
	std::uint8_t trafficClass{};
	std::uint32_t flowLabel{};
	std::uint16_t payloadLength{};
	std::uint8_t nextHeader{};
};

struct TcpHeader {
	std::uint16_t sourcePort{};
	std::uint16_t destinationPort{};
	std::uint8_t headerLength{};
	std::uint16_t flags{};
};

struct UdpHeader {
	std::uint16_t sourcePort{};
	std::uint16_t destinationPort{};
	std::uint16_t length{};
};

ParseResult<EthernetHeader> decodeEthernet(std::span<const std::uint8_t> bytes);
ParseResult<IPv4Header> decodeIPv4(std::span<const std::uint8_t> bytes, std::size_t offset = 14);
ParseResult<IPv6Header> decodeIPv6(std::span<const std::uint8_t> bytes, std::size_t offset = 14);
ParseResult<TcpHeader> decodeTcp(std::span<const std::uint8_t> bytes, std::size_t offset);
ParseResult<UdpHeader> decodeUdp(std::span<const std::uint8_t> bytes, std::size_t offset);

} // namespace core
