#ifndef TALK_PARALLEL_H
#error "include 'parallel.h' instead"
#endif //TALK_PARALLEL_H
#ifndef TALK_INTERNAL_PARALLEL_H
#define TALK_INTERNAL_PARALLEL_H
#include <functional>

template<typename Signature>
void talk::internal::poolHandle<Signature>::step(void *data) {
	poolHandle<Signature>* us = static_cast<poolHandle<Signature>*>(data);
	auto task = std::move(us->tasks.popMov());
	task();
	us->runningTasks--;
	us->runningTasks.notify_all();
}

template<typename Signature>
inline talk::internal::poolHandle<Signature>::poolHandle(const pool& p) : p(p) {
	auto id = std::this_thread::get_id();
	if (p.getThreadIds().contains(id)) {
		// We throw because otherwise we could possibly deadlock
		throw std::runtime_error("PoolHandle is being created from a pool thread");
	}
}

template<typename Signature>
talk::internal::poolHandle<Signature>::~poolHandle() {
	this->tasks.empty_block();
	size_t old = this->runningTasks.load();
	while (old > 0) {
		this->runningTasks.wait(old);
		old = this->runningTasks.load();
	}
}

template<typename T>
inline std::future<T> talk::poolHandle<T(void)>::async(const std::function<T(void)> &f) {
	if (!this->p.queue(this->step, this)) {
		throw std::runtime_error("Pool is not accepting new tasks");
	}
	std::packaged_task<T()> task(f);
	auto future = task.get_future();
	this->runningTasks++;
	this->tasks.pushMov(std::move(task));
	return future;
}

template<typename T, typename... Args>
inline std::future<T> talk::poolHandle<T(Args...)>::async(const std::function<T(Args...)> &f, argPack &args) {
	if (!this->p.queue(this->step, this)) {
		throw std::runtime_error("Pool is not accepting new tasks");
	}

	std::packaged_task<T()> task(std::bind(call, f, args));
	auto future = task.get_future();
	this->runningTasks++;
	this->tasks.pushMov(std::move(task));
	return future;
}

template<typename T>
inline std::vector<std::future<T>> talk::poolHandle<T(void)>::async(const std::function<T(void)> &f, size_t count) {
	std::vector<std::future<T>> futures;
	async(f, count, futures);
	return futures;
}

template<typename T>
inline void talk::poolHandle<T(void)>::
async(const std::function<T(void)> &f, size_t count, std::vector<std::future<T>>& futures) {
	futures.resize(count);
	for (size_t i = 0; i < count; i++) {
		futures[i] = async(f);
	}
}

template <typename T, typename... Args>
inline void talk::poolHandle<T(Args...)>::
async(const std::function<T(Args...)> &f, std::vector<argPack> &args, std::vector<std::future<T>>& futures){
	futures.resize(args.size());
	size_t i = 0;
	for(auto& arg : args){
		futures[i++] = async(f, arg);
	}
}

template<typename T, typename... Args>
inline std::vector<std::future<T>> talk::poolHandle<T(Args...)>::
async(const std::function<T(Args...)> &f, std::vector<argPack> &args) {
	std::vector<std::future<T>> futures;
	async(f, args, futures);
	return futures;
}

template<typename T>
void talk::queue<T>::push(T t) {
	std::lock_guard<std::recursive_mutex> lock(mutex);
	queue.push(t);
	cv.notify_one();
}

template<typename T>
void talk::queue<T>::pushMov(T&& t) {
	std::lock_guard<std::recursive_mutex> lock(mutex);
	queue.push(std::move(t));
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
T talk::queue<T>::popMov() {
	std::unique_lock<std::recursive_mutex> lock(mutex);
	cv.wait(lock, [this] { return !queue.empty(); });
	auto t = std::move(queue.front());
	queue.pop();
	cv_empty.notify_all();
	return std::move(t);
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
