#include <pow.h>
#include <crypto.h>

using namespace talk::crypto;
using talk::bytes;

std::pair<bytes, bytes>
talk::pow(const bytes &data, const size_t &difficulty, const size_t &nonce_size, crypto::kdf &crypt) {
	if (nonce_size == 0)
		throw std::invalid_argument("nonce_size must be greater than 0");

	if (crypt.outLen() <= difficulty)
		throw std::invalid_argument("outLen must be greater than difficulty");

	fRand rand{};
	bytes nonce(nonce_size);
	bytes hash(crypt.outLen());
	bool running = true;
	const size_t left = difficulty%8;
	const size_t full = difficulty/8;

	byte mask = 0;
	for (size_t i = 0; i < left; i++) {
		mask |= 1 << i;
	}

	while (running) [[likely]] {
		rand.randomIn(nonce_size, nonce);
		crypt.deriveKeyIn(nonce, data, hash);
		running = false;
		for(size_t i = hash.size()-1 ; i >= hash.size()-full; i--) {
			if(hash[i] != 0) [[likely]] {
				running = true;
				break;
			}
		}
		running = running || (hash[hash.size()-full-1] & mask) != 0;
	}
	return {nonce, hash};
}

