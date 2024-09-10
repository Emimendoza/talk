#include <talk/crypto.h>
#include <talk/pow.h>
#include <cassert>

using namespace talk;
using namespace talk::crypto;
using std::initializer_list;

int main(){
	bytes nonce = {0x81f8b835fcb69c6b};
	bool result;
	bytes hash = bytes::fromHex("f53b3e8d60c03b2bdb96385f31b83f892cf66b8ca6a6bbd140b1eed8c942999aba22d8f1839a4381b306b2089908c9e116518117fdb54125eb430093ae033b30fb68d6db987c48fefd38530307e43977a8a991657bf5ff2414942906217d42b01f02a5f877fc781e2babba42b0fd9f6d912840467f765af1daf1e8286aa6fe4b3812135e0a1bd24f7eb0ab4734236d9fdb1b8a74c103b4c2f27928c26edfaab2ef9a47f9782a5e9492ffbcf7f8e6f8f0874c4f9d2913daccb8b38c1f630c5670caed23ba54ccd98e136e2bde07477218a65593705f71dc1b146dba988a2c5f47f47aacf9b6101d6a0fc9b0674198d27a10b5a1d4f32617f302bef46aba1a8b1d3607406db8742f55e3670d48e7fe2eb0c94d897f6f5dccb7e8985990b4f94d99060ffe4f9a4bd61480b4f3d55adad80bde9536579e23e3810e4df5dc49dd7b912a6cdc0caaef89fcfd67413e90e4ee31eb917e0eb55bb257a6529cb8f34e8f7d3feb0cf4560b4e195be2f9ac816e72da500ff958aaea0ac0121161ba2352c7a297401e2314789d92377900d6ae8755a487725ea8bb9cb542f7bb92238faaa21d54d62be549acf5bb5c1c3173fa90e87946b9b597b3e2fd6d3c117a63dd9717fdb220352f1cd28a1b43678f1c61949694c5a50a363b49250bdb7467fd4015d9700f80007af1eba4fe8db2db8cef3c0ab8cfe0c8f19cc11fd17ce3b6a647c4d000", result);
	assert(result);
	bytes data = initializer_list<uint8_t>{0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21};

	setMaxThreads(4);
	auto tester = crypto::argon2d(4 , 4, 512, 4);
	auto test = tester.deriveKey(nonce, data, 512);
	assert(test == hash);

	return 0;
}
