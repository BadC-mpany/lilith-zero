A. File System
list_directory: Explore file structure.

read_file: Read content (Source of sensitive data).

write_file: Create/Overwrite content (Sink for data loss/corruption).

search_files: Grep/find files based on pattern.

get_file_info: Metadata check (size, permissions).

B. Network & Web
web_search: General queries (Google/Bing/Brave).

fetch_url / curl: GET requests to read a specific page.

browse_page: Headless browser interaction (rendering JS).

send_request: Generic HTTP request (POST/PUT - highly dangerous).

C. Code Execution
python_repl / execute_python: Runs arbitrary Python code.

shell_execute / bash: Runs system shell commands.

D. System & Productivity
get_time: Current datetime (harmless but essential).

read_clipboard: often contains passwords/keys.

take_screenshot: Vision capability (privacy risk).

send_email: Communication sink.