#ifndef TALK_PARALLEL_H
#error "include 'parallel.h' instead"
#endif //TALK_PARALLEL_H
#ifndef TALK_INTERNAL_PARALLEL_H
#define TALK_INTERNAL_PARALLEL_H

namespace talk {

	template<typename T, typename... Args>
	void poolHandle<T,Args...>::step(void *data) {
		poolHandle<T, Args...>* us = static_cast<poolHandle<T, Args...>*>(data);
		auto task = std::move(us->tasks.pop());
		task();
	}

	template<typename T, typename... Args>
	inline poolHandle<T,Args...>::poolHandle(const std::shared_ptr<pool>& p) : p(p) {}

	template<typename T, typename... Args>
	inline std::future<T> poolHandle<T,Args...>::async(std::function<T(Args...)> f, Args... args) {
		std::packaged_task<T(Args...)> task(f(args...));
		auto future = task.get_future();
		tasks.push(std::move(task));
		p->queue(step, this);
		return future;
	}

	template<typename T, typename... Args>
	poolHandle<T,Args...>::~poolHandle() {
		tasks.empty_block();
	}

	template <typename T, typename... Args>
	inline std::vector<std::future<T>> poolHandle<T,Args...>::async(std::function<T(Args...)> f, std::vector<Args...> args){
		std::vector<std::future<T>> futures;
		futures.reserve(args.size());
		for(auto& arg : args){
			futures.push_back(async(f, arg));
		}
		return futures;
	}

	template<typename T>
	void queue<T>::push(T t) {
		std::lock_guard<std::recursive_mutex> lock(mutex);
		queue.push(t);
		cv.notify_one();
	}

	template<typename T>
	T queue<T>::pop() {
		std::unique_lock<std::recursive_mutex> lock(mutex);
		cv.wait(lock, [this] { return !queue.empty(); });
		auto t = queue.front();
		queue.pop();
		cv_empty.notify_all();
		return t;
	}

	template<typename T>
	bool queue<T>::pop(std::chrono::milliseconds timeout, T& out) {
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
	bool queue<T>::TryPop(T& out) {
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
	bool queue<T>::empty() {
		std::lock_guard<std::recursive_mutex> lock(mutex);
		return queue.empty();
	}

	template<typename T>
	size_t queue<T>::size() {
		std::lock_guard<std::recursive_mutex> lock(mutex);
		return queue.size();
	}

	template<typename T>
	void queue<T>::empty_block() {
		std::unique_lock<std::recursive_mutex> lock(mutex);
		cv_empty.wait(lock, [this] { return queue.empty(); });
	}
}

#endif //TALK_PARALLEL_H
