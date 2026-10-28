#include "PacketDecoder.h"

namespace core {
namespace {
ParseError truncated(std::size_t offset, const char* header) {
	return { offset, std::string("truncated ") + header };
}

std::uint16_t u16(std::span<const std::uint8_t> bytes, std::size_t offset) {
	return static_cast<std::uint16_t>((bytes[offset] << 8) | bytes[offset + 1]);
}
}

ParseResult<EthernetHeader> decodeEthernet(std::span<const std::uint8_t> bytes) {
	if (bytes.size() < 14) return std::unexpected(truncated(bytes.size(), "Ethernet header"));
	return EthernetHeader{ u16(bytes, 12) };
}

ParseResult<IPv4Header> decodeIPv4(std::span<const std::uint8_t> bytes, std::size_t offset) {
	if (offset > bytes.size() || bytes.size() - offset < 20) return std::unexpected(truncated(offset, "IPv4 header"));
	const auto version = static_cast<std::uint8_t>(bytes[offset] >> 4);
	const auto headerLength = static_cast<std::uint8_t>((bytes[offset] & 0x0f) * 4);
	if (version != 4) return std::unexpected(ParseError{ offset, "invalid IPv4 version" });
	if (headerLength < 20) return std::unexpected(ParseError{ offset, "invalid IPv4 IHL" });
	if (bytes.size() - offset < headerLength) return std::unexpected(truncated(offset, "IPv4 options"));
	const auto totalLength = u16(bytes, offset + 2);
	if (totalLength < headerLength) return std::unexpected(ParseError{ offset + 2, "IPv4 total length is smaller than its header" });
	return IPv4Header{ version, headerLength, totalLength,
		static_cast<std::uint16_t>(u16(bytes, offset + 6) & 0x1fff), bytes[offset + 9] };
}

ParseResult<IPv6Header> decodeIPv6(std::span<const std::uint8_t> bytes, std::size_t offset) {
	if (offset > bytes.size() || bytes.size() - offset < 40) return std::unexpected(truncated(offset, "IPv6 header"));
	const auto first = (static_cast<std::uint32_t>(bytes[offset]) << 24) |
		(static_cast<std::uint32_t>(bytes[offset + 1]) << 16) |
		(static_cast<std::uint32_t>(bytes[offset + 2]) << 8) | bytes[offset + 3];
	const auto version = static_cast<std::uint8_t>(first >> 28);
	if (version != 6) return std::unexpected(ParseError{ offset, "invalid IPv6 version" });
	return IPv6Header{ version, static_cast<std::uint8_t>((first >> 20) & 0xff), first & 0xfffff,
		u16(bytes, offset + 4), bytes[offset + 6] };
}

ParseResult<TcpHeader> decodeTcp(std::span<const std::uint8_t> bytes, std::size_t offset) {
	if (offset > bytes.size() || bytes.size() - offset < 20) return std::unexpected(truncated(offset, "TCP header"));
	const auto headerLength = static_cast<std::uint8_t>((bytes[offset + 12] >> 4) * 4);
	if (headerLength < 20) return std::unexpected(ParseError{ offset + 12, "invalid TCP data offset" });
	if (bytes.size() - offset < headerLength) return std::unexpected(truncated(offset, "TCP options"));
	const auto flags = static_cast<std::uint16_t>(((bytes[offset + 12] & 1) << 8) | bytes[offset + 13]);
	return TcpHeader{ u16(bytes, offset), u16(bytes, offset + 2), headerLength, flags };
}

ParseResult<UdpHeader> decodeUdp(std::span<const std::uint8_t> bytes, std::size_t offset) {
	if (offset > bytes.size() || bytes.size() - offset < 8) return std::unexpected(truncated(offset, "UDP header"));
	const auto length = u16(bytes, offset + 4);
	if (length < 8) return std::unexpected(ParseError{ offset + 4, "invalid UDP length" });
	if (bytes.size() - offset < length) return std::unexpected(truncated(offset, "UDP payload"));
	return UdpHeader{ u16(bytes, offset), u16(bytes, offset + 2), length };
}
} // namespace core
