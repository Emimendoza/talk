#ifndef TALK_MESSAGE_H
#define TALK_MESSAGE_H
#include "nodes.h"

namespace talk{

	struct MessageV1{
		// 0x01
		uint8_t protocol;
		// sha512 of the serialized message
		std::byte ID[64];

	};
}

#endif //TALK_MESSAGE_H
