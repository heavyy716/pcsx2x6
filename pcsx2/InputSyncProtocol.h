// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

// Pure (no I/O) pieces of the input sync / lockstep netplay layer, kept separate so they can be unit tested.

#pragma once

#include "common/Pcsx2Types.h"

#include <deque>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace InputSync
{
	static constexpr u32 PROTOCOL_VERSION = 1;
	static constexpr u32 PACKET_MAGIC = 0x4E365850; // "PX6N"
	static constexpr u16 DEFAULT_PORT = 7656;
	static constexpr u32 DEFAULT_DELAY = 3;
	static constexpr u32 MAX_DELAY = 30;
	static constexpr u32 DEFAULT_HASH_INTERVAL = 120;
	static constexpr u32 CHUNK_SIZE = 1024;
	static constexpr u32 MAX_INPUTS_PER_PACKET = 64;

	// One player's input for one frame.
	struct PeerInput
	{
		u16 buttons = 0;
		u8 coins = 0; // coin inserts this frame
		u8 test = 0;  // test switch byte

		bool operator==(const PeerInput& rhs) const = default;
	};

	// Both players' input for one frame (what the game sees).
	struct FrameInput
	{
		u16 buttons[2] = {};
		u8 coins[2] = {};
		u8 test = 0;

		bool operator==(const FrameInput& rhs) const = default;
	};

	// Folds both live local players onto the local side (so a P1-only binding layout works on either side).
	PeerInput MakeLocalInput(const u16 live_buttons[2], const u8 live_coins[2], u8 live_test);

	// Places each side's input in its player slot. side = 0 (P1) or 1 (P2).
	FrameInput CombineInputs(u32 local_side, const PeerInput& local, const PeerInput& remote);

	enum class PacketType : u8
	{
		Hello = 1,
		Welcome = 2,
		Reject = 3,
		Chunk = 4,
		Ready = 5,
		Input = 6,
		Ping = 7,
		Bye = 8,
	};

	enum class RejectReason : u8
	{
		Busy = 1,
		Protocol = 2,
		Build = 3,
		Game = 4,
		Media = 5,
		Bios = 6,
	};

	struct HelloMsg
	{
		u32 protocol = PROTOCOL_VERSION;
		std::string build;
		std::string game;
		u64 media_hash = 0;
		u64 bios_hash = 0;
		u64 dongle_hash = 0;
		u16 dip_bits = 0;

		bool operator==(const HelloMsg& rhs) const = default;
	};

	struct WelcomeMsg
	{
		u32 session = 0;
		u8 client_side = 1;
		u8 delay = DEFAULT_DELAY;
		u16 hash_interval = DEFAULT_HASH_INTERVAL;
		u32 blob_size = 0;
		u64 blob_hash = 0;
		u64 settings_hash = 0;
		u8 warnings = 0; // WarnFlags

		bool operator==(const WelcomeMsg& rhs) const = default;
	};

	enum WarnFlags : u8
	{
		WARN_DONGLE = 1,
		WARN_DIP = 2,
	};

	struct RejectMsg
	{
		RejectReason reason = RejectReason::Busy;
		std::string detail;

		bool operator==(const RejectMsg& rhs) const = default;
	};

	struct ChunkMsg
	{
		u32 session = 0;
		u32 offset = 0;
		u32 total = 0;
		std::vector<u8> data;

		bool operator==(const ChunkMsg& rhs) const = default;
	};

	struct ReadyMsg
	{
		u32 session = 0;
		u64 blob_hash = 0;

		bool operator==(const ReadyMsg& rhs) const = default;
	};

	struct InputMsg
	{
		u32 session = 0;
		u32 ack = 0;        // number of contiguous peer frames the sender has (peer can stop resending below this)
		u32 first_frame = 0; // frame of inputs[0]
		std::vector<PeerInput> inputs;
		u32 hash_frame = 0xFFFFFFFFu; // latest checked frame, or none
		u64 hash = 0;

		bool operator==(const InputMsg& rhs) const = default;
	};

	struct SessionMsg // Ping, Bye
	{
		u32 session = 0;

		bool operator==(const SessionMsg& rhs) const = default;
	};

	std::vector<u8> Encode(const HelloMsg& msg);
	std::vector<u8> Encode(const WelcomeMsg& msg);
	std::vector<u8> Encode(const RejectMsg& msg);
	std::vector<u8> Encode(const ChunkMsg& msg);
	std::vector<u8> Encode(const ReadyMsg& msg);
	std::vector<u8> Encode(const InputMsg& msg);
	std::vector<u8> EncodeSession(PacketType type, const SessionMsg& msg);

	// Returns the packet type if the header is valid.
	std::optional<PacketType> PeekType(std::span<const u8> packet);
	bool Decode(std::span<const u8> packet, HelloMsg* msg);
	bool Decode(std::span<const u8> packet, WelcomeMsg* msg);
	bool Decode(std::span<const u8> packet, RejectMsg* msg);
	bool Decode(std::span<const u8> packet, ChunkMsg* msg);
	bool Decode(std::span<const u8> packet, ReadyMsg* msg);
	bool Decode(std::span<const u8> packet, InputMsg* msg);
	bool DecodeSession(std::span<const u8> packet, PacketType type, SessionMsg* msg);

	const char* GetRejectReasonText(RejectReason reason);

	// Per-frame inputs from one side, kept from the oldest frame still needed.
	class InputQueue
	{
	public:
		void Reset(u32 base_frame = 0);
		void Set(u32 frame, const PeerInput& input); // ignored if already known or too old
		bool Has(u32 frame) const;
		const PeerInput* Get(u32 frame) const;
		u32 ContiguousEnd() const; // first frame not known (all frames before it are known)
		void DiscardBefore(u32 frame);
		u32 GetBase() const { return m_base; }

	private:
		u32 m_base = 0;
		std::deque<std::optional<PeerInput>> m_items;
	};

	// Compares RAM hashes of the same frame from both sides.
	class DesyncTracker
	{
	public:
		enum class Result
		{
			Pending,
			Match,
			Mismatch,
		};

		void Reset();
		Result AddLocal(u32 frame, u64 hash);
		Result AddRemote(u32 frame, u64 hash);
		bool HasDesynced() const { return m_first_desync.has_value(); }
		std::optional<u32> GetFirstDesyncFrame() const { return m_first_desync; }
		u32 GetMatchedCount() const { return m_matched; }

	private:
		Result Check(u32 frame);

		std::map<u32, u64> m_local;
		std::map<u32, u64> m_remote;
		std::optional<u32> m_first_desync;
		u32 m_matched = 0;
	};

	// Settings text: "section/key=value" lines, sorted, used to compare and copy determinism-relevant settings.
	std::string NormalizeSettingsText(std::vector<std::string> lines);
	std::vector<std::pair<std::string, std::string>> ParseSettingsText(std::string_view text); // (section/key, value)

	// "host:port" or "host" (default port). IPv6 literals are not supported.
	bool ParseHostPort(std::string_view text, std::string* host, u16* port);

	// Input recording file (record/replay mode).
	struct RecordingHeader
	{
		std::string game;
		u64 settings_hash = 0;
		u64 sram_hash = 0;
		u64 nvram_hash = 0;
	};
	static constexpr size_t RECORDING_HEADER_SIZE = 64;
	static constexpr size_t RECORDING_FRAME_SIZE = 8;
	std::vector<u8> EncodeRecordingHeader(const RecordingHeader& hdr);
	bool DecodeRecordingHeader(std::span<const u8> data, RecordingHeader* hdr);
	void EncodeRecordingFrame(const FrameInput& in, u8 out[RECORDING_FRAME_SIZE]);
	FrameInput DecodeRecordingFrame(const u8 in[RECORDING_FRAME_SIZE]);
} // namespace InputSync
