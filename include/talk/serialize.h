#ifndef TALK_SERIALIZE_H
#define TALK_SERIALIZE_H
#include <array>
#include <common.h>

namespace talk{
	// All serialization treats numbers as Big Endian

	template<typename T>
	constexpr std::array<byte, sizeof(T)> serialize(T data);

	template<typename T>
	constexpr T deserialize(const std::array<byte, sizeof(T)>& data);

}
#include "internal/serialize.h"

#endif //TALK_SERIALIZE_H
