#pragma once

#include <co2h/bytes.hpp>
#include <co2h/proto.hpp>

#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace co2h::server {

struct Task {
    std::uint64_t id = 0;
    proto::TaskOp op = proto::TaskOp::Noop;
    Bytes         payload;
    std::int64_t  operator_id = 0;
};

// Per-beacon FIFO of pending tasks; pops drained atomically on beacon checkin.
class TaskQueue {
public:
    std::uint64_t enqueue(const std::string& beacon_id,
                          proto::TaskOp op,
                          Bytes payload,
                          std::int64_t operator_id);

    std::vector<Task> drain(const std::string& beacon_id);

    // Returns total queued count across all beacons (for metrics).
    std::size_t size_estimate();

private:
    std::mutex mu_;
    std::uint64_t next_id_ = 1;
    std::unordered_map<std::string, std::deque<Task>> q_;
};

}
