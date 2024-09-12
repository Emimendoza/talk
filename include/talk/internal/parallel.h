#ifndef TALK_PARALLEL_H
#error "include 'parallel.h' instead"
#endif //TALK_PARALLEL_H
#ifndef TALK_INTERNAL_PARALLEL_H
#define TALK_INTERNAL_PARALLEL_H


template<typename Signature>
void talk::internal::poolHandle<Signature>::step(void *data) {
	poolHandle<Signature>* us = static_cast<poolHandle<Signature>*>(data);
	auto task = std::move(us->tasks.pop());
	task();
}

template<typename Signature>
inline talk::internal::poolHandle<Signature>::poolHandle(const std::shared_ptr<pool>& p) : p(p) {
	if (!p) {
		throw std::runtime_error("Pool is nullptr");
	}
	auto id = std::this_thread::get_id();
	if (p->getThreadIds().contains(id)) {
		// We throw because otherwise we could possibly deadlock
		throw std::runtime_error("PoolHandle is being created from a pool thread");
	}
}

template<typename Signature>
talk::internal::poolHandle<Signature>::~poolHandle() {
	tasks.empty_block();
}

template<typename T>
inline std::future<T> talk::poolHandle<T(void)>::async(std::function<T(void)> f) {
	if (!this->p->queue(this->step, this)) {
		throw std::runtime_error("Pool is not accepting new tasks");
	}
	std::packaged_task<T()> task(f());
	auto future = task.get_future();
	this->tasks.push(std::move(task));
	return future;
}

template<typename T, typename... Args>
inline std::future<T> talk::poolHandle<T(Args...)>::async(std::function<T(Args...)> f, Args... args) {
	if (!this->p->queue(this->step, this)) {
		throw std::runtime_error("Pool is not accepting new tasks");
	}
	std::packaged_task<T(Args...)> task(f(args...));
	auto future = task.get_future();
	this->tasks.push(std::move(task));
	return future;
}

template<typename T>
inline std::vector<std::future<T>> talk::poolHandle<T(void)>::async(std::function<T(void)> f, size_t count) {
	std::vector<std::future<T>> futures;
	futures.reserve(count);
	for (size_t i = 0; i < count; i++) {
		futures.push_back(async(f));
	}
	return futures;
}

template <typename T, typename... Args>
inline std::vector<std::future<T>> talk::poolHandle<T(Args...)>::async(std::function<T(Args...)> f, std::vector<Args...> args){
	std::vector<std::future<T>> futures;
	futures.reserve(args.size());
	for(auto& arg : args){
		futures.push_back(async(f, arg));
	}
	return futures;
}

template<typename T>
void talk::queue<T>::push(T t) {
	std::lock_guard<std::recursive_mutex> lock(mutex);
	queue.push(t);
	cv.notify_one();
}

template<typename T>
T talk::queue<T>::pop() {
	std::unique_lock<std::recursive_mutex> lock(mutex);
	cv.wait(lock, [this] { return !queue.empty(); });
	auto t = queue.front();
	queue.pop();
	cv_empty.notify_all();
	return t;
}

template<typename T>
bool talk::queue<T>::pop(std::chrono::milliseconds timeout, T& out) {
	std::unique_lock<std::recursive_mutex> lock(mutex);
	if(cv.wait_for(lock, timeout, [this] { return !queue.empty(); })){
		out = queue.front();
		queue.pop();
		cv_empty.notify_all();
		return true;
	}
	return false;
}

template<typename T>
bool talk::queue<T>::TryPop(T& out) {
	std::lock_guard<std::recursive_mutex> lock(mutex);
	if(queue.empty()){
		return false;
	}
	out = queue.front();
	queue.pop();
	cv_empty.notify_all();
	return true;
}

template<typename T>
bool talk::queue<T>::empty() {
	std::lock_guard<std::recursive_mutex> lock(mutex);
	return queue.empty();
}

template<typename T>
size_t talk::queue<T>::size() {
	std::lock_guard<std::recursive_mutex> lock(mutex);
	return queue.size();
}

template<typename T>
void talk::queue<T>::empty_block() {
	std::unique_lock<std::recursive_mutex> lock(mutex);
	cv_empty.wait(lock, [this] { return queue.empty(); });
}

#endif //TALK_PARALLEL_H
