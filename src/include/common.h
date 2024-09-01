#ifndef TALK_COMMON_H
#define TALK_COMMON_H
#include <cstdint>
#include <cstddef>
#include <vector>

namespace talk {
	enum class Protocol : uint8_t {
		// 0x01
		MESSAGE_V1 = 0x01
	};

	class bytes : public std::vector<std::byte> {
	public:
		// Inherit constructors
		using std::vector<std::byte>::vector;

		/**
		 * @brief Get the data as a uint8_t pointer
		 * @note Do not store the pointer, as it will be invalidated if the vector is resized
		 * @return a pointer to the data
		 */
		uint8_t* data_u8() {
			return reinterpret_cast<uint8_t*>(data());
		}

		/**
		 * @brief Get the data as a uint8_t pointer
		 * @note Do not store the pointer, as it will be invalidated if the vector is resized
		 * @return a pointer to the data
		 */
		[[nodiscard]] const uint8_t* data_u8() const {
			return reinterpret_cast<const uint8_t*>(data());
		}
	};
}

#endif //TALK_COMMON_H
