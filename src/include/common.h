#ifndef TALK_COMMON_H
#define TALK_COMMON_H
#include <cstdint>
#include <cstddef>
#include <vector>

namespace talk{
	enum class Protocol : uint8_t{
		// 0x01
		MESSAGE_V1 = 0x01
	};

	typedef std::vector<std::byte> bytes;
}

#endif //TALK_COMMON_H
