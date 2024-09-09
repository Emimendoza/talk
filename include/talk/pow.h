#ifndef TALK_POW_H
#define TALK_POW_H
#include <common.h>

namespace talk::crypto{
	class kdf;
}

namespace talk{
	/**
	 * @brief will get pow for a given data using kdf crypto object
	 * @param data the data to get a pow for
	 * @param difficulty the difficulty (bits of 0s) to find
	 * @param nonce_size the size of the nonce to find (in bytes)
	 * @param crypt the kdf object to use (unsafe to use the same object for multiple threads)
	 * @param key_size the size of the key for the kdf to produce
	 * @return a pair of the nonce and the hash
	 */
	std::pair<bytes, bytes> pow(const bytes& data, const size_t& difficulty, const size_t& nonce_size,
								crypto::kdf& crypt,
								const size_t& key_size);
}

#endif //TALK_POW_H
