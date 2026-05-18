#pragma once

#include "bytes.hpp"
#include "proto.hpp"

#include <cstdint>
#include <deque>
#include <optional>

namespace co2h {

// Stream decoder for the operator wire frame:
//   [u32 be length][u8 type][bytes payload]
// Feed bytes with feed(); pull complete frames with next().
class FrameDecoder {
public:
    explicit FrameDecoder(std::uint32_t max_frame = proto::kMaxFrameLen) noexcept
        : max_frame_(max_frame) {}

    void feed(BytesView chunk);

    // Pops a ready frame, or std::nullopt if not enough data.
    std::optional<proto::Frame> next();

    bool too_large() const noexcept { return too_large_; }

private:
    Bytes         buf_;
    std::uint32_t max_frame_;
    bool          too_large_ = false;
};

// Encodes a single frame into dst (appends).
void encode_frame(Bytes& dst, proto::MsgType type, BytesView payload);

}
