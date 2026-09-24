//===----------------------------------------------------------------------===//
// ext_hooks.hpp — the base every event contract builds on (charter R1–R4, R7, R8; spec 008)
//
// A producer (an extension that emits events) and its consumers (an exporter such as acl-otel) share a
// registry held in the instance's ObjectCache and reached by name, stamped with the contract's magic and
// version and read only through Reach(). Consumers register sinks; the producer composes an event on its
// decision path, pushes it onto a bounded Delivery queue, and a delivery thread hands it to every sink.
// A slow or failing sink costs a counted drop, never latency on the decision (R8).
//
//   using MyHooks = ext_common::Registry<MyEvent, MY_MAGIC, MY_VERSION>;   // in the contract header
//   auto hooks = MyHooks::Reach(db.GetObjectCache(), "my_hooks", why);      // either side, any load order
//   hooks->AddSink(my_sink);                                               // a consumer
//
// Everything is header-only (R1): each side compiles its own copy, and the stamp - the first two data
// members of the registry - is what keeps two copies from reading one object through two layouts. A
// contract bumps its version on any change to what it lays out, this base included (R4).
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/common/shared_ptr.hpp"
#include "duckdb/common/string.hpp"
#include "duckdb/common/vector.hpp"
#include "duckdb/storage/object_cache.hpp"

#include <condition_variable>
#include <cstdint>
#include <deque>
#include <exception>
#include <functional>
#include <map>
#include <mutex>
#include <thread>
#include <utility>

namespace duckdb {
namespace ext_common {

//! One metric row, as a scrape wants it. Attributes only from bounded sets (R7).
struct Metric {
	string name;
	string kind; // counter / gauge
	vector<std::pair<string, string>> attributes;
	int64_t value = 0;
	string unit;
	string description;
};

inline string AttributesKey(const vector<std::pair<string, string>> &attributes) {
	string key;
	for (auto &attribute : attributes) {
		key += attribute.first + "=" + attribute.second + "\x1f";
	}
	return key;
}

//! Counters: a value per (name, attribute tuple), added to by the producer, read by a consumer.
class Counters {
public:
	void Add(const string &name, const vector<std::pair<string, string>> &attributes, int64_t delta = 1) {
		auto key = name + "\x1f" + AttributesKey(attributes);
		std::lock_guard<std::mutex> guard(lock);
		auto entry = values.find(key);
		if (entry == values.end()) {
			values[key] = delta;
			keys[key] = {name, attributes};
		} else {
			entry->second += delta;
		}
	}
	int64_t Get(const string &name, const vector<std::pair<string, string>> &attributes) const {
		auto key = name + "\x1f" + AttributesKey(attributes);
		std::lock_guard<std::mutex> guard(lock);
		auto entry = values.find(key);
		return entry == values.end() ? 0 : entry->second;
	}
	vector<Metric> Snapshot() const {
		std::lock_guard<std::mutex> guard(lock);
		vector<Metric> out;
		for (auto &entry : values) {
			auto &named = keys.at(entry.first);
			Metric metric;
			metric.name = named.first;
			metric.kind = "counter";
			metric.attributes = named.second;
			metric.value = entry.second;
			metric.unit = "1";
			out.push_back(std::move(metric));
		}
		return out;
	}

private:
	mutable std::mutex lock;
	std::map<string, int64_t> values;
	std::map<string, std::pair<string, vector<std::pair<string, string>>>> keys;
};

//! Gauges: states, read at snapshot time through the reader the owner of the state registered. An owner
//! whose state goes away removes its readers first, so a snapshot never calls into freed memory.
class Gauges {
public:
	using Reader = std::function<int64_t()>;

	void Register(const string &name, const vector<std::pair<string, string>> &attributes, const string &unit,
	              const string &description, Reader reader) {
		std::lock_guard<std::mutex> guard(lock);
		entries.push_back(Entry {name, attributes, unit, description, std::move(reader)});
	}
	void Remove(const string &name) {
		std::lock_guard<std::mutex> guard(lock);
		for (auto it = entries.begin(); it != entries.end();) {
			it = it->name == name ? entries.erase(it) : it + 1;
		}
	}
	vector<Metric> Snapshot() const {
		vector<Entry> copy;
		{
			std::lock_guard<std::mutex> guard(lock);
			copy = entries;
		}
		vector<Metric> out;
		for (auto &entry : copy) {
			Metric metric;
			metric.name = entry.name;
			metric.kind = "gauge";
			metric.attributes = entry.attributes;
			metric.value = entry.reader();
			metric.unit = entry.unit;
			metric.description = entry.description;
			out.push_back(std::move(metric));
		}
		return out;
	}

private:
	struct Entry {
		string name;
		vector<std::pair<string, string>> attributes;
		string unit;
		string description;
		Reader reader;
	};
	mutable std::mutex lock;
	vector<Entry> entries;
};

//! A consumer of events. Called on the producer's delivery thread, in `seq` order, never on the decision
//! path; an exception is caught, counted and skipped for that event.
template <class Event>
struct Sink {
	virtual ~Sink() = default;
	virtual void OnEvent(const Event &event) = 0;
	//! Called when the producer stops, and whenever it flushes.
	virtual void Flush() {
	}
};

//! The registry of one contract, per DatabaseInstance. The stamp comes first (R3): an object under the key
//! stamped otherwise is refused by Reach() and never dereferenced beyond the stamp.
template <class Event, int32_t MAGIC, int32_t VERSION>
class Registry : public ObjectCacheEntry {
public:
	int32_t contract_magic = MAGIC;
	int32_t contract_version = VERSION;

	static constexpr int32_t CONTRACT_MAGIC = MAGIC;
	static constexpr int32_t CONTRACT_VERSION = VERSION;

	//! Never evicted: a registration must outlive any cache pressure.
	optional_idx GetEstimatedCacheMemory() const override {
		return optional_idx();
	}

	//! The registry of an instance under `key`, created when absent (either side, any load order) and
	//! checked: null with `why` when the object under the key is stamped with another magic or version.
	template <class Derived>
	static shared_ptr<Derived> ReachAs(ObjectCache &cache, const string &key, string &why) {
		auto registry = cache.GetOrCreate<Derived>(key);
		if (!registry) {
			why = "the object cache holds something else under '" + key + "'";
			return nullptr;
		}
		if (registry->contract_magic != MAGIC) {
			why = "the registry under '" + key + "' carries another contract's stamp";
			return nullptr;
		}
		if (registry->contract_version != VERSION) {
			why = "the registry under '" + key + "' is stamped with contract version " +
			      std::to_string(registry->contract_version) + ", this build speaks " + std::to_string(VERSION) +
			      " - the two sides were built from different revisions of the contract";
			return nullptr;
		}
		why.clear();
		return registry;
	}

	void AddSink(shared_ptr<Sink<Event>> sink) {
		std::lock_guard<std::mutex> guard(lock);
		sinks.push_back(std::move(sink));
	}
	void RemoveSink(const shared_ptr<Sink<Event>> &sink) {
		std::lock_guard<std::mutex> guard(lock);
		for (auto it = sinks.begin(); it != sinks.end(); ++it) {
			if (*it == sink) {
				sinks.erase(it);
				return;
			}
		}
	}
	//! The sinks as they are now (a copy: one may be removed while the delivery thread runs).
	vector<shared_ptr<Sink<Event>>> Sinks() const {
		std::lock_guard<std::mutex> guard(lock);
		return sinks;
	}
	//! Is anyone listening: a producer composes no event when nobody is.
	bool HasSinks() const {
		std::lock_guard<std::mutex> guard(lock);
		return !sinks.empty();
	}
	Counters &GetCounters() {
		return counters;
	}
	Gauges &GetGauges() {
		return gauges;
	}

private:
	mutable std::mutex lock;
	vector<shared_ptr<Sink<Event>>> sinks;
	Counters counters;
	Gauges gauges;
};

//! The producer's side of delivery: a bounded queue and one thread that hands each event to the sinks the
//! `sinks` function returns (and to `local`, the producer's own sink - a log - if any). Push never blocks:
//! a full queue drops the event and counts it. Owned by the producer, in its own image (R1).
template <class Event>
class Delivery {
public:
	using SinksOf = std::function<vector<shared_ptr<Sink<Event>>>()>;
	using Count = std::function<void(const string &what)>; // "dropped", "sink_failed"

	Delivery(size_t capacity_p, SinksOf sinks_p, Count count_p)
	    : capacity(capacity_p), sinks(std::move(sinks_p)), count(std::move(count_p)) {
		worker = std::thread([this]() { Run(); });
	}
	~Delivery() {
		Stop();
	}
	Delivery(const Delivery &) = delete;
	Delivery &operator=(const Delivery &) = delete;

	//! Queue an event; false (and counted) when the queue is full or delivery has stopped.
	bool Push(Event event) {
		{
			std::lock_guard<std::mutex> guard(lock);
			if (stopping || queue.size() >= capacity) {
				if (count) {
					count("dropped");
				}
				return false;
			}
			queue.push_back(std::move(event));
		}
		ready.notify_one();
		return true;
	}
	//! Deliver what is queued, then stop the thread and flush the sinks. Idempotent.
	void Stop() {
		{
			std::lock_guard<std::mutex> guard(lock);
			if (stopping) {
				return;
			}
			stopping = true;
		}
		ready.notify_all();
		if (worker.joinable()) {
			worker.join();
		}
		for (auto &sink : sinks()) {
			try {
				sink->Flush();
			} catch (...) {
			}
		}
	}

private:
	void Run() {
		while (true) {
			Event event;
			{
				std::unique_lock<std::mutex> guard(lock);
				ready.wait(guard, [&]() { return stopping || !queue.empty(); });
				if (queue.empty()) {
					return;
				}
				event = std::move(queue.front());
				queue.pop_front();
			}
			for (auto &sink : sinks()) {
				try {
					sink->OnEvent(event);
				} catch (...) {
					if (count) {
						count("sink_failed");
					}
				}
			}
		}
	}

	size_t capacity;
	SinksOf sinks;
	Count count;
	std::mutex lock;
	std::condition_variable ready;
	std::deque<Event> queue;
	bool stopping = false;
	std::thread worker;
};

} // namespace ext_common
} // namespace duckdb
