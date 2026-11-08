// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

// Rollback feasibility probe (vs-rollback harness). Enabled by PCSX2X6_RBPROBE=<log path>.
// Periodically measures unthrottled speed, in-memory savestate cost, and replay determinism.
// All hooks run on the CPU thread from VSyncStart (Counters.cpp).
namespace RollbackProbe
{
	extern bool s_active;

	void BeforeThrottleImpl();
	void OnVSyncImpl();
	bool SkipThrottleImpl();

	// Before the frame limiter: marks the end of this frame's emulation work.
	static inline void BeforeThrottle()
	{
		if (s_active)
			BeforeThrottleImpl();
	}

	// True while replaying recorded frames (they run unthrottled, like a real rollback).
	static inline bool SkipThrottle()
	{
		return s_active && SkipThrottleImpl();
	}

	// After input polling at vsync start: the point where states are saved/loaded.
	static inline void OnVSync()
	{
		if (s_active)
			OnVSyncImpl();
	}
} // namespace RollbackProbe
