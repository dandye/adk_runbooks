#!/usr/bin/env python3
"""
ADK Session Metrics & Token Statistics Extractor.

Usage:
    python get_session_stats.py <session_id>
    python get_session_stats.py latest
"""

import sys
import sqlite3
import json
from datetime import datetime, timezone
from pathlib import Path

def format_duration(seconds: float) -> str:
    mins = int(seconds // 60)
    secs = seconds % 60
    if mins > 0:
        return f"{mins}m {secs:.1f}s ({seconds:.2f}s)"
    return f"{secs:.2f}s"

def get_session_stats(session_id: str = "latest"):
    db_path = Path(__file__).resolve().parent / "manager" / ".adk" / "session.db"
    if not db_path.exists():
        print(f"Error: Session database not found at {db_path}")
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    if session_id == "latest":
        cursor.execute("SELECT id FROM sessions ORDER BY update_time DESC LIMIT 1")
        row = cursor.fetchone()
        if not row:
            print("No sessions found in database.")
            return
        session_id = row[0]

    cursor.execute(
        "SELECT id, timestamp, event_data FROM events WHERE session_id = ? ORDER BY id ASC",
        (session_id,)
    )
    rows = cursor.fetchall()

    if not rows:
        print(f"No events found for session: {session_id}")
        return

    prompt_tokens = 0
    candidates_tokens = 0
    total_tokens = 0
    tool_calls = []
    agent_stats = {}
    timestamps = []

    for row in rows:
        ev_id, ts, data_str = row
        if ts:
            timestamps.append(float(ts))

        data = json.loads(data_str)
        author = data.get("author", "unknown")
        
        if author not in agent_stats:
            agent_stats[author] = {
                "events": 0,
                "prompt_tokens": 0,
                "candidates_tokens": 0,
                "total_tokens": 0,
                "tool_calls": 0
            }
        agent_stats[author]["events"] += 1

        usage = data.get("usage_metadata") or data.get("metadata", {}).get("usage_metadata")
        if usage:
            p_tok = usage.get("prompt_token_count", 0)
            c_tok = usage.get("candidates_token_count", 0)
            t_tok = usage.get("total_token_count", 0)
            prompt_tokens += p_tok
            candidates_tokens += c_tok
            total_tokens += t_tok
            agent_stats[author]["prompt_tokens"] += p_tok
            agent_stats[author]["candidates_tokens"] += c_tok
            agent_stats[author]["total_tokens"] += t_tok

        content = data.get("content", {})
        if content:
            for p in content.get("parts", []):
                if "function_call" in p:
                    fc = p["function_call"]
                    tool_calls.append({
                        "agent": author,
                        "tool": fc.get("name"),
                        "args": fc.get("args", {})
                    })
                    agent_stats[author]["tool_calls"] += 1

    # Calculate Wall Clock Time
    if timestamps:
        start_ts = min(timestamps)
        end_ts = max(timestamps)
        duration_sec = end_ts - start_ts
        start_str = datetime.fromtimestamp(start_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        end_str = datetime.fromtimestamp(end_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        duration_str = format_duration(duration_sec)
    else:
        start_str = "N/A"
        end_str = "N/A"
        duration_str = "N/A"
        duration_sec = 0.0

    print("=" * 75)
    print(f"  ADK SESSION METRICS: {session_id}")
    print("=" * 75)
    print(f"  Session Start Time:          {start_str}")
    print(f"  Session End Time:            {end_str}")
    print(f"  Wall Clock Execution Time:   {duration_str}")
    print(f"  Total Events (Turns):        {len(rows)}")
    print(f"  Total Prompt Tokens (Up):    {prompt_tokens:,}")
    print(f"  Total Output Tokens (Down):  {candidates_tokens:,}")
    print(f"  Total Tokens (All LLMs):     {total_tokens:,}")
    print("=" * 75)

    print("\n[PER-AGENT METRICS]")
    for ag, st in agent_stats.items():
        print(f"  * {ag:<20} | Events: {st['events']:<2} | Tool Calls: {st['tool_calls']:<2} | Prompt: {st['prompt_tokens']:>9,} | Output: {st['candidates_tokens']:>6,}")

    print(f"\n[TOOL CALLS CHRONOLOGY ({len(tool_calls)} total)]")
    for i, tc in enumerate(tool_calls, 1):
        args_str = str(tc["args"])
        if len(args_str) > 75:
            args_str = args_str[:72] + "..."
        print(f"  {i:2d}. [{tc['agent']:<18}] -> {tc['tool']}({args_str})")
    print("=" * 75)

if __name__ == "__main__":
    sid = sys.argv[1] if len(sys.argv) > 1 else "latest"
    get_session_stats(sid)
