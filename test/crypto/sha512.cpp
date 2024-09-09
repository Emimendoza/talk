#include <talk/crypto.h>
#include <cassert>
using namespace talk::crypto;
using talk::bytes;

int main(){
	auto* sha512 = new talk::crypto::sha512();
	assert(sha512->getType() == type_t::SHA512);

	// test vectors
	bytes out;

	const bytes expected ={
			(uint64_t)0xcf83e1357eefb8bd,
			(uint64_t)0xf1542850d66d8007,
			(uint64_t)0xd620e4050b5715dc,
			(uint64_t)0x83f4a921d36ce9ce,
			(uint64_t)0x47d0d13c5d85f2b0,
			(uint64_t)0xff8318d2877eec2f,
			(uint64_t)0x63b931bd47417a81,
			(uint64_t)0xa538327af927da3e
	};

	// empty string
	sha512->digestUpdate({});
	out = sha512->digestFinal();

	assert(out == expected);

	delete sha512;
	return 0;
}