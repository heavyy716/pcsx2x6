// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "InputSyncProtocol.h"

#include <gtest/gtest.h>

using namespace InputSync;

template <typename T>
static T RoundTrip(const T& msg)
{
	const std::vector<u8> data = Encode(msg);
	T out;
	EXPECT_TRUE(Decode(data, &out));
	return out;
}

TEST(InputSync, HelloRoundTrip)
{
	HelloMsg msg;
	msg.build = "v2.3.4 abcdef";
	msg.game = "NM00027";
	msg.media_hash = 0x1122334455667788ull;
	msg.bios_hash = 0x99AABBCCDDEEFF00ull;
	msg.dongle_hash = 42;
	msg.dip_bits = 0x70;
	EXPECT_EQ(RoundTrip(msg), msg);
	EXPECT_EQ(PeekType(Encode(msg)), PacketType::Hello);
}

TEST(InputSync, WelcomeRejectChunkReadyRoundTrip)
{
	WelcomeMsg welcome;
	welcome.session = 0xDEADBEEF;
	welcome.client_side = 0;
	welcome.delay = 7;
	welcome.hash_interval = 60;
	welcome.blob_size = 34816;
	welcome.blob_hash = 123456789;
	welcome.settings_hash = 987654321;
	welcome.warnings = WARN_DONGLE | WARN_DIP;
	EXPECT_EQ(RoundTrip(welcome), welcome);

	RejectMsg reject{RejectReason::Game, "NM00017"};
	EXPECT_EQ(RoundTrip(reject), reject);
	EXPECT_NE(GetRejectReasonText(RejectReason::Build)[0], '\0');

	ChunkMsg chunk;
	chunk.session = 5;
	chunk.offset = 2048;
	chunk.total = 4096;
	chunk.data.assign(CHUNK_SIZE, 0xAB);
	EXPECT_EQ(RoundTrip(chunk), chunk);

	ReadyMsg ready{5, 0xFFFFFFFFFFFFFFFFull};
	EXPECT_EQ(RoundTrip(ready), ready);
}

TEST(InputSync, InputAndSessionRoundTrip)
{
	InputMsg msg;
	msg.session = 77;
	msg.ack = 100;
	msg.first_frame = 98;
	for (u32 i = 0; i < MAX_INPUTS_PER_PACKET; i++)
		msg.inputs.push_back(PeerInput{static_cast<u16>(i * 3), static_cast<u8>(i & 1), static_cast<u8>(i == 5 ? 0x80 : 0)});
	msg.hash_frame = 120;
	msg.hash = 0x0123456789ABCDEFull;
	EXPECT_EQ(RoundTrip(msg), msg);

	SessionMsg bye{99};
	const std::vector<u8> data = EncodeSession(PacketType::Bye, bye);
	EXPECT_EQ(PeekType(data), PacketType::Bye);
	SessionMsg out;
	EXPECT_TRUE(DecodeSession(data, PacketType::Bye, &out));
	EXPECT_EQ(out, bye);
}

TEST(InputSync, RejectsMalformedPackets)
{
	HelloMsg hello;
	hello.game = "NM00027";
	std::vector<u8> data = Encode(hello);

	// Truncated
	HelloMsg out;
	EXPECT_FALSE(Decode(std::span<const u8>(data.data(), data.size() - 1), &out));

	// Wrong type
	WelcomeMsg welcome;
	EXPECT_FALSE(Decode(data, &welcome));

	// Bad magic
	data[0] ^= 0xFF;
	EXPECT_FALSE(PeekType(data).has_value());
	EXPECT_FALSE(Decode(data, &out));

	// Too short for a header
	const u8 tiny[2] = {1, 2};
	EXPECT_FALSE(PeekType(tiny).has_value());
}

TEST(InputSync, CombineInputsPlacesSides)
{
	const PeerInput local{0x0011, 1, 0};
	const PeerInput remote{0x2200, 0, 0x80};

	const FrameInput p1 = CombineInputs(0, local, remote);
	EXPECT_EQ(p1.buttons[0], 0x0011);
	EXPECT_EQ(p1.buttons[1], 0x2200);
	EXPECT_EQ(p1.coins[0], 1);
	EXPECT_EQ(p1.coins[1], 0);
	EXPECT_EQ(p1.test, 0x80);

	// The other machine sees the same frame when it combines its own view.
	const FrameInput p2 = CombineInputs(1, remote, local);
	EXPECT_EQ(p1, p2);
}

TEST(InputSync, MakeLocalInputFoldsPlayers)
{
	const u16 buttons[2] = {0x0001, 0x0100};
	const u8 coins[2] = {200, 100};
	const PeerInput in = MakeLocalInput(buttons, coins, 0x40);
	EXPECT_EQ(in.buttons, 0x0101);
	EXPECT_EQ(in.coins, 0xFF);
	EXPECT_EQ(in.test, 0x40);
}

TEST(InputSync, InputQueue)
{
	InputQueue q;
	q.Reset(10);
	EXPECT_FALSE(q.Has(10));
	EXPECT_EQ(q.ContiguousEnd(), 10u);

	q.Set(12, PeerInput{3, 0, 0});
	EXPECT_TRUE(q.Has(12));
	EXPECT_EQ(q.ContiguousEnd(), 10u);

	q.Set(10, PeerInput{1, 0, 0});
	q.Set(11, PeerInput{2, 0, 0});
	EXPECT_EQ(q.ContiguousEnd(), 13u);

	// First value wins (redundant resends don't change history).
	q.Set(11, PeerInput{99, 0, 0});
	EXPECT_EQ(q.Get(11)->buttons, 2);

	// Too old is ignored.
	q.Set(5, PeerInput{7, 0, 0});
	EXPECT_FALSE(q.Has(5));

	q.DiscardBefore(12);
	EXPECT_EQ(q.GetBase(), 12u);
	EXPECT_FALSE(q.Has(11));
	EXPECT_EQ(q.Get(12)->buttons, 3);

	// Garbage frame numbers don't allocate.
	q.Set(0xFFFFFFF0u, PeerInput{1, 0, 0});
	EXPECT_FALSE(q.Has(0xFFFFFFF0u));
}

TEST(InputSync, DesyncTracker)
{
	DesyncTracker t;
	EXPECT_EQ(t.AddLocal(120, 0xAA), DesyncTracker::Result::Pending);
	EXPECT_EQ(t.AddRemote(120, 0xAA), DesyncTracker::Result::Match);
	EXPECT_EQ(t.GetMatchedCount(), 1u);
	EXPECT_FALSE(t.HasDesynced());

	EXPECT_EQ(t.AddRemote(240, 0xBB), DesyncTracker::Result::Pending);
	EXPECT_EQ(t.AddLocal(240, 0xBC), DesyncTracker::Result::Mismatch);
	EXPECT_TRUE(t.HasDesynced());
	EXPECT_EQ(t.GetFirstDesyncFrame(), 240u);

	EXPECT_EQ(t.AddLocal(360, 1), DesyncTracker::Result::Pending);
	EXPECT_EQ(t.AddRemote(360, 2), DesyncTracker::Result::Mismatch);
	EXPECT_EQ(t.GetFirstDesyncFrame(), 240u);

	t.Reset();
	EXPECT_FALSE(t.HasDesynced());
	EXPECT_EQ(t.GetMatchedCount(), 0u);
}

TEST(InputSync, SettingsText)
{
	const std::string text = NormalizeSettingsText({"b/y=2", "a/x=1", "c/z=hello=world"});
	EXPECT_EQ(text, "a/x=1\nb/y=2\nc/z=hello=world\n");

	const auto parsed = ParseSettingsText(text + "garbage\n=novalue\n");
	ASSERT_EQ(parsed.size(), 3u);
	EXPECT_EQ(parsed[0].first, "a/x");
	EXPECT_EQ(parsed[0].second, "1");
	EXPECT_EQ(parsed[2].first, "c/z");
	EXPECT_EQ(parsed[2].second, "hello=world");
}

TEST(InputSync, ParseHostPort)
{
	std::string host;
	u16 port = 0;
	EXPECT_TRUE(ParseHostPort("192.168.1.5", &host, &port));
	EXPECT_EQ(host, "192.168.1.5");
	EXPECT_EQ(port, DEFAULT_PORT);

	EXPECT_TRUE(ParseHostPort(" example.com:9000 ", &host, &port));
	EXPECT_EQ(host, "example.com");
	EXPECT_EQ(port, 9000);

	EXPECT_FALSE(ParseHostPort("", &host, &port));
	EXPECT_FALSE(ParseHostPort("host:0", &host, &port));
	EXPECT_FALSE(ParseHostPort("host:65536", &host, &port));
	EXPECT_FALSE(ParseHostPort("host:12ab", &host, &port));
	EXPECT_FALSE(ParseHostPort(":7656", &host, &port));
	EXPECT_FALSE(ParseHostPort("::1", &host, &port));
}

TEST(InputSync, RecordingFormat)
{
	RecordingHeader hdr;
	hdr.game = "NM00027";
	hdr.settings_hash = 1;
	hdr.sram_hash = 2;
	hdr.nvram_hash = 3;
	const std::vector<u8> data = EncodeRecordingHeader(hdr);
	ASSERT_EQ(data.size(), RECORDING_HEADER_SIZE);

	RecordingHeader out;
	ASSERT_TRUE(DecodeRecordingHeader(data, &out));
	EXPECT_EQ(out.game, hdr.game);
	EXPECT_EQ(out.settings_hash, 1u);
	EXPECT_EQ(out.sram_hash, 2u);
	EXPECT_EQ(out.nvram_hash, 3u);

	std::vector<u8> bad = data;
	bad[0] = 'X';
	EXPECT_FALSE(DecodeRecordingHeader(bad, &out));

	FrameInput frame;
	frame.buttons[0] = 0xBEEF;
	frame.buttons[1] = 0x1234;
	frame.coins[0] = 2;
	frame.coins[1] = 1;
	frame.test = 0x80;
	u8 buf[RECORDING_FRAME_SIZE];
	EncodeRecordingFrame(frame, buf);
	EXPECT_EQ(DecodeRecordingFrame(buf), frame);
}
