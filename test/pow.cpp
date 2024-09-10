#include <talk/crypto.h>
#include <talk/pow.h>
#include <iostream>

using namespace talk;

int main() {
	crypto::argon2d crypt(1 , 1, 65536, 1);

	// Hello World!
	bytes data = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21};

	crypto::setMaxThreads(4);
	auto [nonce, hash] = pow(data, 32, 4, crypt, 128);

	std::cout << "nonce: ";
	auto n = nonce.toArray<4>();
	for (auto i : n) {
		std::cout << std::hex << (int)i << " ";
	}
	std::cout << std::endl;
	return 0;
}
