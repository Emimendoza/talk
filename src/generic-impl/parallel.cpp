#include <parallel.h>

using namespace talk;

namespace{
	typedef std::pair<std::function<void(void*)>, void*> task;
	struct p_impl{
		std::condition_variable cv;
		std::mutex mutex;
		std::unique_ptr<std::thread[]> threads;
		size_t threads_size{};
		talk::queue<task> tasks;
		std::atomic<bool> stop = false;
		std::unordered_set<std::thread::id> threadIds;
		~p_impl();
	};
}

static void threadFunc(p_impl* p){
	while(true){
		if(p->stop && p->tasks.empty()){
			p->cv.notify_all();
			return;
		}
		std::unique_lock<std::mutex> lock(p->mutex);
		p->cv.wait(lock, [p]{return p->stop || !p->tasks.empty();});
		task t;
		if(!p->tasks.TryPop(t)){
			continue;
		}
		lock.unlock();
		t.first(t.second);
		p->cv.notify_one();
	}
}


struct talk::pool::impl : public p_impl{
	friend pool;
	std::mutex mutex;
};

pool::pool(size_t threads){
	if (threads == 0) threads = 1;
	pimpl = std::make_shared<impl>();
	pimpl->threads = std::make_unique<std::thread[]>(threads);
	pimpl->threadIds.reserve(threads);
	for(size_t i = 0 ; i < threads ; i++){
		pimpl->threads[i] = std::thread(threadFunc, pimpl.get());
		pimpl->threadIds.insert(pimpl->threads[i].get_id());
	}
	pimpl->threads_size = threads;
}

bool pool::queue(const std::function<void(void *)>& f, void *data) {
	std::unique_lock<std::mutex> lock(pimpl->mutex);
	if (pimpl->stop) return false;
	pimpl->tasks.pushMov({f, data});
	pimpl->cv.notify_one();
	return true;
}

pool::~pool() = default;

p_impl::~p_impl() {
	stop = true;
	cv.notify_all();
	tasks.empty_block();
	for(size_t i = 0 ; i < threads_size ; i++){
		threads[i].join();
	}
}

const std::unordered_set<std::thread::id>& pool::getThreadIds() const{
	std::unique_lock<std::mutex> lock(pimpl->mutex);
	return pimpl->threadIds;
}

pool &pool::operator=(const pool &other) {
	if (this == &other) return *this;
	volatile auto temp = pimpl;
	{
		std::unique_lock<std::mutex> lock(pimpl->mutex);
		pimpl = other.pimpl;
	}
	return *this;
}

