
# Building

For building this documentation site locally:
1. Navigate to the git top-level directory (`adk_runbooks`).
2. Synchronize dependencies using `uv` and `just`:
   ```bash
   just sync
   ```
3. Build the Sphinx HTML documentation:
   ```bash
   just html
   ```
4. View the site by opening `build/html/index.html` in your browser.
