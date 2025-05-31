
# Building

For building this documentation site locally:
1. Navigate to the git top-level directory (likely `adk_runbooks`).
2. Ensure you have a Python virtual environment activated.
3. Install dependencies:
   ```bash
   pip install -r requirements-docs.txt
   ```
4. Build the documentation:
   ```bash
   make html
   ```
5. View the site by opening `build/html/index.html` in your browser.
