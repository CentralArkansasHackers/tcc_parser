README
TCCParser
TCCParser is a command-line utility written in Swift that reads and parses the macOS TCC (Transparency, Consent, and Control) database. It enumerates application permissions on the host and highlights particularly powerful or sensitive permissions useful in a penetration testing or red-team engagement context.

Features
Low-Level: Uses raw SQLite calls (<sqlite3.h>) to retrieve TCC permissions.

Filtering & Highlighting: Flags common “interesting” services such as Accessibility, Screen Capture, Full Disk Access, Apple Events, Microphone, and Camera.

Tabular Output: Displays columns for service name, client (bundle ID/path), auth state, prompt count, last modified time, and sandbox ID.

Help/Usage Menu: Simple command-line options to specify TCC path or show usage.

Security & Legal Disclaimer
Root/SIP: On a modern macOS system, direct access to TCC data is restricted. You may need root privileges or disable SIP for direct SQLite reads.

Ethical Use: This tool is for legitimate testing, research, or forensic purposes. It should not be used for malicious activity.

Stability: Do not modify the TCC database; only read from it. Changing entries can cause unpredictable system behavior or break Apple’s security model.

Apple Updates: The TCC schema or location can change. Verify the current TCC structure on the macOS version you are testing.

Usage
bash
Copy
Edit
TCCParser [options]

OPTIONS:
  -p, --path <path>   Path to the TCC.db file. Defaults to
                      ~/Library/Application Support/com.apple.TCC/TCC.db
  -h, --help          Print this help and exit
Examples
Parse user TCC:

bash
Copy
Edit
./TCCParser
or

bash
Copy
Edit
./TCCParser.swift
Parse system-wide TCC (requires root or SIP disabled):

bash
Copy
Edit
sudo ./TCCParser --path "/Library/Application Support/com.apple.TCC/TCC.db"
Compilation Instructions
Prerequisites:

macOS environment with Xcode Command Line Tools installed.

Swift 5 (or later).

Compile:

bash
Copy
Edit
# If you're using Xcode tools, just run:
swiftc TCCParser.swift -o TCCParser
This produces a binary called TCCParser in the current directory.

Run:

bash
Copy
Edit
./TCCParser -h
./TCCParser
Or specify --path to point to a different TCC.db file.

Make Script Executable (Optional):

bash
Copy
Edit
chmod +x TCCParser.swift
./TCCParser.swift
Output Format
A typical output line (not including the header) looks like this:

yaml
Copy
Edit
  kTCCServiceAccessibility            com.example.AppName                  Allowed    0          2025-03-22 14:57:23  com.example.AppName
A line prefixed with * indicates an “interesting” service from a pentester’s perspective (e.g., Accessibility or Screen Capture with Allowed status).

Further Recommendations
Script Automation: Integrate TCCParser output into larger pentest scripts by piping into grep/awk/jq or other command-line tools.

Privilege Checking: For fully automated use, check for root privileges or catch the errors that occur if reading TCC fails.

Schema Examination: To see the TCC schema (especially on different macOS versions), you could run sqlite3 "/path/to/TCC.db" ".schema access" in a terminal.

