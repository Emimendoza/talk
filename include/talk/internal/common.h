#ifndef TALK_INTERNAL_COMMON_H
#define TALK_INTERNAL_COMMON_H
#include <serialize.h>
#include <cstring>
#include <stdexcept>

#ifndef TALK_COMMON_H
#error "include 'common.h' instead"
#endif //TALK_COMMON_H


namespace talk::internal{
	constexpr std::array<const char, 16> HexChars = {
		'0', '1', '2', '3',
		'4', '5', '6', '7',
		'8', '9', 'a', 'b',
		'c', 'd', 'e', 'f'
	};
	constexpr std::array<const char, 16> UpperHexChars = {
		'0', '1', '2', '3',
		'4', '5', '6', '7',
		'8', '9', 'A', 'B',
		'C', 'D', 'E', 'F'
	};
	constexpr bool hexToByte(const char& hex, byte& out){
		if(hex >= '0' && hex <= '9'){
			out |= static_cast<byte>(hex - '0');
			return true;
		}
		if(hex >= 'a' && hex <= 'f'){
			out |= static_cast<byte>(hex - 'a' + 10);
			return true;
		}
		if(hex >= 'A' && hex <= 'F'){
			out |= static_cast<byte>(hex - 'A' + 10);
			return true;
		}
		return false;
	}
}


namespace talk{

	template<typename T>
	constexpr bytes::bytes(std::initializer_list<T> list){
		reserve(list.size() * sizeof(T));
		for (const auto& item : list){
			const auto& data = serialize(item);
			insert(end(), data.begin(), data.end());
		}
	}

	[[nodiscard]]
	constexpr bytes bytes::fromHex(const std::string_view& hex, bool& success){
		if(hex.size() % 2 != 0){
			success = false;
			return {};
		}
		bytes ret;
		ret.reserve(hex.size() / 2);
		for(size_t i = 0; i < hex.size(); i += 2){
			byte byte = 0;
			if(!internal::hexToByte(hex[i], byte)){
				success = false;
				return {};
			}
			byte <<= 4;
			if(!internal::hexToByte(hex[i + 1], byte)){
				success = false;
				return {};
			}
			ret.push_back(byte);
		}
		success = true;
		return ret;
	}

	constexpr std::string bytes::toHex(const bool &upper) const {
		std::string ret;
		ret.reserve(size() * 2);
		const auto& hexChars = upper ? internal::UpperHexChars : internal::HexChars;
		for (const auto& byte : *this) {
			ret.push_back(hexChars[static_cast<uint8_t>(byte) >> 4]);
			ret.push_back(hexChars[static_cast<uint8_t>(byte) & 0x0F]);
		}
		return ret;
	}

	template<size_t N>
	constexpr byteArr<N> bytes::toArray(const size_t& start) const {
		byteArr<N> ret{};
		if (size() < start + N) {
			throw std::out_of_range("Not enough data");
		}
		std::memcpy(ret.data(), data() + start, N);
		return ret;
	}

	template<size_t N>
	inline void bytes::append(const byteArr<N>& data){
		insert(end(), data.begin(), data.end());
	}

	template<size_t N>
	inline bytes& bytes::operator+=(const byteArr<N>& data){
		append(data);
		return *this;
	}

	inline void bytes::append(const bytes& data){
		insert(end(), data.begin(), data.end());
	}

	inline bytes& bytes::operator+=(const bytes& data){
		append(data);
		return *this;
	}
}

#endif //TALK_INTERNAL_COMMON_H
