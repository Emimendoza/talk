#include <talk-private/threads.h>
#include <common.h>

using namespace talk;
using namespace talk::internal;

namespace {
	class generic_threads final : public threads{
	public:
		std::mutex m{};
		std::vector<threads*> t{};
		std::atomic<size_t> maxThreads{1};
		void setMaxThreads(size_t threads) override {
			maxThreads = threads;
		}
		size_t getMaxThreads() override {
			return maxThreads;
		}
		generic_threads(){
			registerThread();
		}
	};
	generic_threads _generic_threads{};
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

void threads::registerThread() {
	std::lock_guard<std::mutex> lock(getMutex());
	getThreads().push_back(this);
}
