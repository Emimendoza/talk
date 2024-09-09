#include <talk/crypto.h>
#include <cassert>
#include <memory>

using namespace talk;
using talk::bytes;

int main() {
	std::unique_ptr<crypto::sha256> sha256(new crypto::sha256());

	assert(sha256->getType() == crypto::type_t::SHA256);

	// Test vectors

	bytes out, expected;
	bool result;

	// Empty string
	sha256->digestUpdate({});
	out = sha256->digestFinal();
	expected = bytes::fromHex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", result);
	assert(result);
	assert(out == expected);

	sha256->digestReset();
	sha256->digestUpdate(bytes::fromHex("08912389abcd3a", result));
	assert(result);
	sha256->digestReset();
	sha256->digestUpdate(bytes::fromHex("", result));
	assert(result);
	out = sha256->digestFinal();
	assert(out == expected);

	sha256->digestReset();
	bytes a = {'a'};
	for (size_t i = 0; i < 1000000; i++) {
		sha256->digestUpdate(a);
		assert(result);
	}
	out = sha256->digestFinal();
	expected = bytes::fromHex("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", result);
	assert(result);
	assert(out == expected);


	return 0;
}