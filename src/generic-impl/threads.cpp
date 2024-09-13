#include <talk-private/threads.h>
#include <parallel.h>
#include <common.h>
#include <crypto.h>

using namespace talk;
using namespace talk::internal;


namespace talk::internal {
#ifdef TALK_USE_OPENSSL
	class openssl_threads;
	extern openssl_threads _ot;
#endif
}



namespace{
	class generic_threads final : public threads{
	public:
		generic_threads();
		std::mutex m{};
		std::vector<threads*> t{};
		std::atomic<size_t> maxThreads{1};
		void setMaxThreads(size_t threads) override {
			maxThreads = threads;
			crypto::cryptoPool = pool(threads);
		}
	private:
		void registerThread(void* thread){
			std::lock_guard<std::mutex> lock(m);
			t.push_back((threads*) thread);
		}
	};
	generic_threads _generic_threads{};
}

pool talk::crypto::cryptoPool = pool(1);

size_t threads::getMaxThreads(){
	return _generic_threads.maxThreads;
}

generic_threads::generic_threads() {
	registerThread(&_generic_threads);
#ifdef TALK_USE_OPENSSL
	registerThread(&_ot);
#endif
}

void talk::setMaxThreads(size_t threads) {
	threads::SMT(threads);
}

const std::atomic<size_t>& talk::getMaxThreads() {
	return _generic_threads.maxThreads;
}

size_t talk::getMinMaxThreads() {
	std::lock_guard<std::mutex> lock(_generic_threads.m);
	size_t min = _generic_threads.maxThreads;
	for(const auto& i : _generic_threads.t){
		min = std::min(min, i->getMaxThreads());
	}
	return min;
}

std::mutex& threads::getMutex() {
	return _generic_threads.m;
}

std::vector<threads*>& threads::getThreads() {
	return _generic_threads.t;
}

void threads::SMT(size_t threads) {
	std::lock_guard<std::mutex> lock(getMutex());
	for(const auto& i : getThreads()){
		i->setMaxThreads(threads);
	}
}
