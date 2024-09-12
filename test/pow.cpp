#include <talk/crypto.h>
#include <talk/pow.h>
#include <iostream>
#include <iomanip>

using namespace talk;

int main() {
	crypto::argon2d crypt(4, 512, 4, 512);

	// Hello World!
	bytes data = std::initializer_list<byte>{0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21};

	setMaxThreads(4);
	auto [nonce, hash] = pow(data, 12, 8, crypt);

	std::cout << "nonce: ";
	auto n = nonce.toArray<8>();
	for (auto i : n) {
		std::cout << std::hex << (int)i << " ";
	}

	std::cout << std::endl << "hash: ";
	auto h = hash.toArray<512>();
	for (auto i : h) {
		std::cout << std::hex <<  std::setfill('0') << std::setw(2) << (int)i;
	}
	std::cout << std::endl;

	auto tester = crypto::argon2d(4, 512, 4, 512);

	auto test = tester.deriveKey(nonce, data);

	return test != hash;
}
