//===----------------------------------------------------------------------===//
// ext_hooks.hpp — the base every event contract builds on (charter R1–R4, R7, R8; spec 008)
//
// A producer (an extension that emits events) and its consumers (an exporter such as acl-otel) share a
// registry held in the instance's ObjectCache and reached by name, stamped with the contract's magic and
// version and read only through Reach(). Consumers register sinks; the producer composes an event on its
// decision path, pushes it onto a bounded Delivery queue, and a delivery thread hands it to every sink.
// A slow or failing sink costs a counted drop, never latency on the decision (R8).
//
//   class MyHooks : public ext_common::Registry<MyEvent, MY_MAGIC, MY_VERSION> {   // the contract header
//   public:
//       static string ObjectType() { return "my_hooks"; }                         // the cache key
//       string GetObjectType() override { return ObjectType(); }
//   };
//   auto hooks = MyHooks::ReachAs<MyHooks>(db.GetObjectCache(), why);   // either side, any load order
//   hooks->AddSink(my_sink);                                            // a consumer
//
// Everything is header-only (R1): each side compiles its own copy, and the stamp - the first data members
// of the registry: the contract's magic and version, and this base's version - is what keeps two copies
// from reading one object through two layouts. A contract bumps its version on any change to what it lays
// out (R4); a change to this base bumps EXT_HOOKS_VERSION, which every registry carries and checks too.
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
#include <memory>
#include <mutex>
#include <thread>
#include <utility>

namespace duckdb {
namespace ext_common {

//! The layout of this base (Registry, Counters, Gauges, Sink): stamped in every registry, checked by ReachAs.
constexpr int32_t EXT_HOOKS_VERSION = 1;

//! One metric row, as a scrape wants it. Attributes only from bounded sets (R7).
struct Metric {
	string name;
	string kind; // counter / gauge
	vector<std::pair<string, string>> attributes;
	int64_t value = 0;
	string unit;
	string description;
};

//! A key for an attribute tuple: each name and value length-prefixed, so no two tuples share one. Order counts
//! - a producer names a metric's attributes in one fixed order.
inline string AttributesKey(const vector<std::pair<string, string>> &attributes) {
	string key;
	for (auto &attribute : attributes) {
		key += std::to_string(attribute.first.size()) + ":" + attribute.first;
		key += std::to_string(attribute.second.size()) + ":" + attribute.second;
	}
	return key;
}

//! Counters: a value per (name, attribute tuple), added to by the producer, read by a consumer.
class Counters {
public:
	void Add(const string &name, const vector<std::pair<string, string>> &attributes, int64_t delta = 1) {
		auto key = AttributesKey({{name, string()}}) + AttributesKey(attributes);
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
		auto key = AttributesKey({{name, string()}}) + AttributesKey(attributes);
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

//! Gauges: states, read at snapshot time through the reader the owner of the state registered. Readers run
//! under the gauges' lock, so once Remove returns its reader never runs again and the owner may free the
//! state: a reader must be cheap (an atomic load, a size under the owner's own short lock) and must not
//! call back into these gauges.
class Gauges {
public:
	using Reader = std::function<int64_t()>;

	//! One gauge per (name, attributes): registering it again replaces the reader.
	void Register(const string &name, const vector<std::pair<string, string>> &attributes, const string &unit,
	              const string &description, Reader reader) {
		std::lock_guard<std::mutex> guard(lock);
		for (auto &entry : entries) {
			if (entry.name == name && entry.attributes == attributes) {
				entry.unit = unit;
				entry.description = description;
				entry.reader = std::move(reader);
				return;
			}
		}
		entries.push_back(Entry {name, attributes, unit, description, std::move(reader)});
	}
	void Remove(const string &name, const vector<std::pair<string, string>> &attributes) {
		std::lock_guard<std::mutex> guard(lock);
		for (auto it = entries.begin(); it != entries.end();) {
			it = it->name == name && it->attributes == attributes ? entries.erase(it) : it + 1;
		}
	}
	//! A reader that throws is left out of this snapshot.
	vector<Metric> Snapshot() const {
		std::lock_guard<std::mutex> guard(lock);
		vector<Metric> out;
		for (auto &entry : entries) {
			Metric metric;
			metric.name = entry.name;
			metric.kind = "gauge";
			metric.attributes = entry.attributes;
			try {
				metric.value = entry.reader();
			} catch (...) {
				continue;
			}
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

//! A consumer of events. Called on the producer's delivery thread, in the order the producer pushed them,
//! never on the decision path; an exception is caught, counted and skipped for that event. The delivery
//! thread holds its own reference: OnEvent may still be running, or run once more, after RemoveSink
//! returns - a sink owns (by shared_ptr) everything it touches.
template <class Event>
struct Sink {
	virtual ~Sink() = default;
	virtual void OnEvent(const Event &event) = 0;
	//! Called when the producer's delivery stops, after the last event.
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
	int32_t hooks_version = EXT_HOOKS_VERSION;

	static constexpr int32_t CONTRACT_MAGIC = MAGIC;
	static constexpr int32_t CONTRACT_VERSION = VERSION;

	//! Never evicted: a registration must outlive any cache pressure.
	optional_idx GetEstimatedCacheMemory() const override {
		return optional_idx();
	}

	//! The registry of an instance under Derived::ObjectType(), created when absent (either side, any load
	//! order) and checked: null with `why` when the object under the key is of another type (the cache
	//! compares type names before any cast) or stamped with another magic or version.
	template <class Derived>
	static shared_ptr<Derived> ReachAs(ObjectCache &cache, string &why) {
		auto key = Derived::ObjectType();
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
		if (registry->hooks_version != EXT_HOOKS_VERSION) {
			why = "the registry under '" + key + "' is built on hooks base version " +
			      std::to_string(registry->hooks_version) + ", this build on " + std::to_string(EXT_HOOKS_VERSION) +
			      " - the two sides were built from different revisions of duckdb-ext-common";
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

//! The producer's side of delivery: a bounded queue and one thread that hands each event, in push order, to
//! the sinks the `sinks` function returns. Push never blocks: a full queue drops the event and counts it.
//! Nothing that goes wrong on the delivery thread leaves it (R8). Owned by the producer, in its own image
//! (R1), and stopped by it - from one thread, never from a static at process exit. A producer that stamps
//! a sequence number does so under its own lock around Push, so the numbers arrive in order.
template <class Event>
class Delivery {
public:
	using SinksOf = std::function<vector<shared_ptr<Sink<Event>>>()>;
	using Count = std::function<void(const string &what)>; // "dropped", "sink_failed"

	Delivery(size_t capacity, SinksOf sinks, Count count) : state(std::make_shared<State>()) {
		state->capacity = capacity;
		state->sinks = std::move(sinks);
		state->count = std::move(count);
		auto shared = state; // the thread owns the state too: it may outlive this object (Stop from a sink)
		worker = std::thread([shared]() { Run(*shared); });
	}
	~Delivery() {
		Stop();
	}
	Delivery(const Delivery &) = delete;
	Delivery &operator=(const Delivery &) = delete;

	//! Queue an event; false (and counted) when the queue is full or delivery has stopped.
	bool Push(Event event) {
		bool accepted = false;
		{
			std::lock_guard<std::mutex> guard(state->lock);
			if (!state->stopping && state->queue.size() < state->capacity) {
				state->queue.push_back(std::move(event));
				accepted = true;
			}
		}
		if (accepted) {
			state->ready.notify_one();
		} else {
			Tally(*state, "dropped");
		}
		return accepted;
	}
	//! Deliver what is queued, then stop the thread and flush the sinks. Idempotent. Called from a sink (on
	//! the delivery thread) it does not wait: the thread delivers what is queued, flushes and ends on its own.
	void Stop() {
		{
			std::lock_guard<std::mutex> guard(state->lock);
			if (state->stopping) {
				return;
			}
			state->stopping = true;
		}
		state->ready.notify_all();
		if (!worker.joinable()) {
			return;
		}
		if (worker.get_id() == std::this_thread::get_id()) {
			worker.detach();
			return;
		}
		worker.join();
	}

private:
	struct State {
		size_t capacity = 0;
		SinksOf sinks;
		Count count;
		std::mutex lock;
		std::condition_variable ready;
		std::deque<Event> queue;
		bool stopping = false;
	};

	static vector<shared_ptr<Sink<Event>>> Current(State &state) {
		try {
			return state.sinks ? state.sinks() : vector<shared_ptr<Sink<Event>>>();
		} catch (...) {
			return vector<shared_ptr<Sink<Event>>>();
		}
	}
	static void Tally(State &state, const string &what) {
		try {
			if (state.count) {
				state.count(what);
			}
		} catch (...) {
		}
	}
	//! The delivery thread: every queued event to every sink, until stopped and drained; then the flush.
	static void Run(State &state) {
		while (true) {
			Event event;
			{
				std::unique_lock<std::mutex> guard(state.lock);
				state.ready.wait(guard, [&]() { return state.stopping || !state.queue.empty(); });
				if (state.queue.empty()) {
					break;
				}
				event = std::move(state.queue.front());
				state.queue.pop_front();
			}
			for (auto &sink : Current(state)) {
				try {
					sink->OnEvent(event);
				} catch (...) {
					Tally(state, "sink_failed");
				}
			}
		}
		for (auto &sink : Current(state)) {
			try {
				sink->Flush();
			} catch (...) {
			}
		}
	}

	shared_ptr<State> state;
	std::thread worker;
};

} // namespace ext_common
} // namespace duckdb
