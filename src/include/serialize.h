#ifndef TALK_SERIALIZE_H
#define TALK_SERIALIZE_H
#include <array>
#include <cstddef>
#include <cstdint>

namespace talk::serialize{
	constexpr std::array<std::byte, 1> serialize_u8(const uint8_t& data);
	constexpr std::array<std::byte, 2> serialize_u16(const uint16_t& data);
	constexpr std::array<std::byte, 4> serialize_u32(const uint32_t& data);
	constexpr std::array<std::byte, 8> serialize_u64(const uint64_t& data);

	constexpr uint8_t deserialize_u8(const std::array<std::byte, 1>& data);
	constexpr uint16_t deserialize_u16(const std::array<std::byte, 2>& data);
	constexpr uint32_t deserialize_u32(const std::array<std::byte, 4>& data);
	constexpr uint64_t deserialize_u64(const std::array<std::byte, 8>& data);

}


#endif //TALK_SERIALIZE_H
