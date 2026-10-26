# Charmbracelet VHS Tape for adk_runbooks: Basic Setup & Running the Multi-Agent System
# Run with: vhs adk_runbooks_quickstart.tape

Output adk_runbooks_quickstart.mp4
Output adk_runbooks_quickstart.webm

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

# Pre-stage real Argolis .env off-camera so secrets never appear in plain text
Hide
Type "ENV_SRC=$HOME/Projects/adk_runbooks__worktrees/envs/progressive_discovery_mcp_v0001__multi-agent__manager__.env"
Enter
Sleep 200ms
Show

# --- Part 1: Basic Setup ---
Type "# 1. Clone the repository with submodules"
Enter
Type "REPO_URL=\"https://github.com/dandye/adk_runbooks.git\""
Enter
Type "git clone --recurse-submodules \"$REPO_URL\" && cd adk_runbooks"
Enter
Sleep 2s

Type "# 2. Ensure submodules are initialized and activate virtual environment"
Enter
Type "git submodule update --init --recursive"
Enter
Type "python3 -m venv venv && source venv/bin/activate"
Enter
Sleep 1s

Type "# 3. Install multi-agent requirements"
Enter
Type "pip install -r multi-agent/requirements.txt"
Enter
Sleep 2s

Type "# 4. Copy Argolis .env configuration (dandye-0324-chronicle)"
Enter
Hide
Type "cp \"$ENV_SRC\" multi-agent/manager/.env"
Enter
Show
Type "cp multi-agent/manager/.env.example multi-agent/manager/.env"
Enter
Type "sed -E 's/(KEY|APIKEY)=.*/\\1=********/' multi-agent/manager/.env"
Enter
Sleep 2s

# --- Part 2: Running the Multi-Agent System ---
Type "# 5. Run the Multi-Agent System CLI (adk run manager)"
Enter
Type "cd multi-agent && adk run manager"
Enter
Sleep 3s

Type "Triage suspicious login activity for user alice@example.com from IP 198.51.100.42"
Enter
Sleep 15s

Type "exit"
Enter
Sleep 1s

Type "# 6. Launch the interactive ADK Web UI"
Enter
Type "adk web --port 8000"
Enter
Sleep 4s
