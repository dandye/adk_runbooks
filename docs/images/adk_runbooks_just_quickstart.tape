# Charmbracelet VHS Tape for adk_runbooks (just + uv variation):
# Basic Setup & Running the Multi-Agent System
# Run with: vhs adk_runbooks_just_quickstart.tape

Output adk_runbooks_just_screencast.mp4
Output adk_runbooks_just_screencast.webm

Set Shell "bash"
Set FontFamily "JetBrains Mono"
Set FontSize 18
Set Width 1920
Set Height 1080
Set Padding 32
Set Theme "TokyoNight"
Set WindowBar "Colorful"
Set WindowBarSize 44
Set TypingSpeed 35ms

# Pre-stage Argolis .env off-camera so secrets are never printed in plain text
Hide
Type "ENV_SRC=$HOME/Projects/adk_runbooks__worktrees/envs/progressive_discovery_mcp_v0001__multi-agent__manager__.env"
Enter
Sleep 200ms
Show

# --- Part 1: Basic Setup (just + uv) ---
Type "# 1. Clone the repository with submodules"
Enter
Type "REPO_URL=\"https://github.com/dandye/adk_runbooks.git\""
Enter
Type "git clone --recurse-submodules \"$REPO_URL\" && cd adk_runbooks"
Enter
Sleep 2s

Type "# 2. List available just recipes and run just setup"
Enter
Type "just"
Enter
Sleep 1.5s
Type "just setup"
Enter
Sleep 2s

Type "# 3. Auto-discover Argolis SecOps configuration (dandye-0324-chronicle)"
Enter
Hide
Type "cp \"$ENV_SRC\" multi-agent/manager/.env"
Enter
Show
Type "CHRONICLE_API_URL=\"projects/1002894625780/locations/us/instances/7e977ce4-f45d-43b2-aea0-52f8b66acd80\""
Enter
Type "just config-auto-discover \"$CHRONICLE_API_URL\""
Enter
Sleep 2.5s

# --- Part 2: Running the Multi-Agent System (just run-manager & just adk-web) ---
Type "# 4. Run the interactive Manager CLI"
Enter
Type "just run-manager"
Enter
Sleep 3s

Type "Triage suspicious login activity for user alice@example.com from IP 198.51.100.42"
Enter
Sleep 15s

Type "exit"
Enter
Sleep 1s

Type "# 5. Launch the interactive ADK Web UI"
Enter
Type "just adk-web"
Enter
Sleep 4s
