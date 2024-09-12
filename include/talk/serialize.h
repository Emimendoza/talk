#ifndef TALK_SERIALIZE_H
#define TALK_SERIALIZE_H
#include <common.h>

namespace talk{
	// Default Serialization treats numbers as big-endian
	// Use this type for serialization

	template<typename T>
	constexpr byteArr<sizeof(T)> serialize(T data);

	template<typename T>
	constexpr T deserialize(const byteArr<sizeof(T)>& data);

	// Serialization in little-endian
	// Only use this if absolutely necessary (e.g. for network protocols or if specified in a standard)

	template<typename T>
	constexpr byteArr<sizeof(T)> serializeLE(T data);

	template<typename T>
	constexpr T deserializeLE(const byteArr<sizeof(T)>& data);

}
#include "internal/serialize.h"

#endif //TALK_SERIALIZE_H
