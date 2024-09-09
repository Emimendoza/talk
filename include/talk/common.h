#ifndef TALK_COMMON_H
#define TALK_COMMON_H
#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>

namespace talk {
	enum class Protocol : uint8_t {
		// 0x01
		MESSAGE_V1 = 0x01
	};

	typedef std::uint8_t byte;

	class bytes : public std::vector<byte> {
	public:
		// Inherit constructors
		using std::vector<byte>::vector;

		template<typename T>
		constexpr bytes(std::initializer_list<T> list);

		/**
		 * @brief Construct a bytes object from a hex string
		 * @param hex the hex string
		 * @param success whether the conversion was successful
		 */
		[[nodiscard]] static constexpr
		bytes fromHex(const std::string_view& hex, bool& success);

		/**
		 * @brief Convert the data to a hex string
		 * @param upper whether to use uppercase or lowercase letters
		 * @return the hex string
		 */
		[[nodiscard]] constexpr std::string toHex(const bool& upper) const;

		/**
		 * @brief Get the data as a uint8_t pointer
		 * @note Do not store the pointer, as it will be invalidated if the vector is resized
		 * @return a pointer to the data
		 */
		constexpr uint8_t* dataU8();

		/**
		 * @brief Get the data as a uint8_t pointer
		 * @note Do not store the pointer, as it will be invalidated if the vector is resized
		 * @return a pointer to the data
		 */
		[[nodiscard]] constexpr const uint8_t* dataU8() const;

		template<size_t N>
		[[nodiscard]] constexpr std::array<byte, N> toArray(const size_t& start = 0) const;
	};

	// Represents empty bytes (no data)
	static constexpr bytes EMPTY{};
}

#include "internal/common.h"
#endif //TALK_COMMON_H
