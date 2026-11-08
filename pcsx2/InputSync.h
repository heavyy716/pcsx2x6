// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

// Input sync: deterministic per-frame arcade (JVS) input for record/replay and delay-based lockstep netplay.
// Both machines run the same game; only each frame's inputs travel over the network.

#pragma once

#include "common/Pcsx2Types.h"

#include <string>

class Error;
class SettingsInterface;

namespace InputSync
{
	enum class Mode : u8
	{
		Off,
		Record,
		Replay,
		Host,
		Join,
	};

	struct Options
	{
		Mode mode = Mode::Off;
		std::string path;    // recording file (Record/Replay)
		std::string address; // host address (Join)
		u16 port = 7656;
		u32 side = 0;      // 0 = P1, 1 = P2 (Host only; the joining side gets the other one)
		u32 delay = 3;     // frames of input delay (Host decides)
		u32 hash_interval = 120; // frames between RAM hashes
		u32 timeout_ms = 10000;  // in-game disconnect timeout
		std::string hash_log;    // optional text file of "frame hash" lines
		u32 stop_after_frames = 0; // shut down after this many frames (testing)
	};

	struct SessionInfo
	{
		std::string game_id;
		std::string elf_path;
		s64 media_size = 0;
		std::string dongle_path;
	};

	/// Sets options for the next VM boot only (consumed by Prepare()).
	void SetPendingOptions(const Options& options);
	bool HasPendingOptions();
	void ClearPendingOptions();

	/// Called at the start of VM initialization. Makes IsActive() true when a session was requested.
	void Prepare();

	/// True while a record/replay/netplay session is configured for the current VM.
	bool IsActive();
	bool IsNetplay();
	Mode GetMode();

	/// Connects to the peer (netplay) or opens the recording, and syncs the starting state.
	/// Called during VM initialization after the game is identified and before the CPU reset.
	bool Connect(const SessionInfo& info, Error* error);

	/// Cancels a connect in progress (from the UI thread).
	void CancelConnect();

	/// Ends the session and closes sockets/files.
	void EndSession();

	/// Overrides determinism-relevant settings (called from LoadCoreSettings while active).
	void ApplyCoreSettingOverrides(SettingsInterface& si);

	/// Called once per emulated frame at vsync, after host input has been polled.
	void OnVsync();

	/// Short status text for UI (empty when inactive).
	std::string GetStatusText();
} // namespace InputSync
