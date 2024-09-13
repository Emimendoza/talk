#ifndef TALK_COMMON_H
#define TALK_COMMON_H
#include <atomic>
#include <cstdint>
#include <cstddef>
#include <vector>
#include <array>
#include <string>

namespace talk {
	class pool;

	// Sets the amount of threads in all pools
	void setMaxThreads(size_t threads);
	const std::atomic<size_t>& getMaxThreads();
	size_t getMinMaxThreads();

	enum class Protocol : uint8_t {
		// 0x01
		MESSAGE_V1 = 0x01
	};

	typedef std::uint8_t byte;

	// Very common, so the shorthand is useful
	template<size_t N>
	using byteArr = std::array<byte, N>;

	class bytes : public std::vector<byte> {
	public:
		// Inherit constructors
		using std::vector<byte>::vector;

		template<typename T>
		constexpr bytes(std::initializer_list<T> list);

		template<size_t N>
		explicit constexpr bytes(const byteArr<N>& data);

		/**
		 * @brief Construct a bytes object from a hex string
		 * @param hex the hex string
		 * @param success whether the conversion was successful
		 */
		[[nodiscard]] static constexpr
		inline bytes fromHex(const std::string_view& hex, bool& success);

		/**
		 * @brief Convert the data to a hex string
		 * @param upper whether to use uppercase or lowercase letters
		 * @return the hex string
		 */
		[[nodiscard]] constexpr std::string toHex(const bool& upper) const;

		template<size_t N>
		[[nodiscard]] constexpr byteArr<N> toArray(const size_t& start = 0) const;

		template<size_t N>
		inline void append(const byteArr<N>& data);

		inline void append(const bytes& data);

		template<size_t N>
		inline bytes& operator+=(const byteArr<N>& data);

		inline bytes& operator+=(const bytes& data);
	};

	// Represents empty bytes (no data)
	static constexpr bytes EMPTY{};
}

#include "internal/common.h"
#endif //TALK_COMMON_H
