#ifndef TALK_INTERNAL_SERIALIZE_TPP
#define TALK_INTERNAL_SERIALIZE_TPP

#ifndef TALK_SERIALIZE_H
// Don't include this file directly, use 'serialize.h' instead
#error "include 'serialize.h' instead"
#endif //TALK_SERIALIZE_H

namespace talk{

	template<typename T>
	constexpr T deserialize(const byteArr<sizeof(T)>& data){
		T ret = 0;
		for (const auto& byte : data){
			ret |= byte;
			ret <<= 8;
		}
		return ret;
	}

	template<typename T>
	constexpr byteArr<sizeof(T)> serialize(T data){
		byteArr<sizeof(T)> ret;
		for (auto i = sizeof(T); i> 0 ; i--){
			ret[i-1] = data & 0xFF;
			data >>= 8;
		}
		return ret;
	}

	template<typename T>
	constexpr T deserializeLE(const byteArr<sizeof(T)>& data){
		T ret = 0;
		size_t i = 0;
		for (const auto& byte : data){
			ret |= byte << (i*8);
			i++;
		}
		return ret;
	}

	template<typename T>
	constexpr byteArr<sizeof(T)> serializeLE(T data){
		byteArr<sizeof(T)> ret;
		for (size_t i = 0; i < sizeof(T); i++){
			ret[i] = data & 0xFF;
			data >>= 8;
		}
		return ret;
	}
}


#endif //TALK_INTERNAL_SERIALIZE_TPP
