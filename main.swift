#!/usr/bin/swift

import Foundation
import SQLite3

// MARK: - Utility Structures

/// Holds a single TCC record with relevant fields for analysis
struct TCCRecord {
    let service: String
    let client: String
    let authValue: Int
    let promptCount: Int
    let lastModifiedEpoch: Int64
    let sandboxId: String
    
    /// Convert lastModifiedEpoch (Unix time in seconds) to a human-readable string
    var lastModifiedDateString: String {
        let date = Date(timeIntervalSince1970: TimeInterval(lastModifiedEpoch))
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter.string(from: date)
    }
    
    /// Provide a short textual interpretation of authValue
    var authDescription: String {
        // Common interpretation of TCC auth_value
        // 0 = Denied, 1 = Allowed, 2 = Prompt (or restricted), 3 = Limited?
        // This can vary by macOS version. Expand if needed.
        switch authValue {
        case 0:  return "Denied"
        case 1:  return "Allowed"
        case 2:  return "Prompt"
        default: return "Other(\(authValue))"
        }
    }
}

// MARK: - Command-Line Parser & Main Logic

/// Parses the local TCC database and returns an array of TCC records
func parseTCCDatabase(atPath dbPath: String) -> [TCCRecord] {
    var records: [TCCRecord] = []
    var db: OpaquePointer? = nil
    
    // Attempt to open the database read-only
    let openFlags = SQLITE_OPEN_READONLY
    if sqlite3_open_v2(dbPath, &db, openFlags, nil) != SQLITE_OK {
        let errMsg = String(cString: sqlite3_errmsg(db))
        fputs("[-] ERROR: Unable to open TCC database (\(dbPath)): \(errMsg)\n", stderr)
        return records
    }
    
    defer {
        // Cleanup
        sqlite3_close(db)
    }
    
    // This query may vary if Apple changes the schema. Adjust columns as needed.
    let query = """
    SELECT
        service,
        client,
        auth_value,
        prompt_count,
        last_modified,
        CASE WHEN indirect_object_identifier IS NULL THEN '' ELSE indirect_object_identifier END AS sandbox_id
    FROM access;
    """
    
    var statement: OpaquePointer? = nil
    if sqlite3_prepare_v2(db, query, -1, &statement, nil) != SQLITE_OK {
        let errMsg = String(cString: sqlite3_errmsg(db))
        fputs("[-] ERROR: SQL prepare failed: \(errMsg)\n", stderr)
        return records
    }
    
    defer {
        sqlite3_finalize(statement)
    }
    
    // Iterate over rows
    while sqlite3_step(statement) == SQLITE_ROW {
        let servicePtr  = sqlite3_column_text(statement, 0)
        let clientPtr   = sqlite3_column_text(statement, 1)
        let authValue   = sqlite3_column_int(statement, 2)
        let promptCount = sqlite3_column_int(statement, 3)
        let lastMod     = sqlite3_column_int64(statement, 4)
        let sandboxPtr  = sqlite3_column_text(statement, 5)
        
        let serviceStr  = servicePtr  != nil ? String(cString: servicePtr!)  : ""
        let clientStr   = clientPtr   != nil ? String(cString: clientPtr!)   : ""
        let sandboxStr  = sandboxPtr  != nil ? String(cString: sandboxPtr!)  : ""
        
        let record = TCCRecord(
            service: serviceStr,
            client: clientStr,
            authValue: Int(authValue),
            promptCount: Int(promptCount),
            lastModifiedEpoch: lastMod,
            sandboxId: sandboxStr
        )
        records.append(record)
    }
    
    return records
}

/// Print usage/help menu
func printHelp(programName: String) {
    let usage = """
    TCCParser - A macOS TCC database parser for pentesters

    USAGE:
      \(programName) [options]

    OPTIONS:
      -p, --path <path>   Path to the TCC.db file. If not provided, defaults to
                          ~/Library/Application Support/com.apple.TCC/TCC.db
      -h, --help          Print this help and exit

    DESCRIPTION:
      TCCParser reads macOS TCC databases, enumerates local app permissions,
      and prints them in a table with fields that can be useful for a security
      assessment. Run this tool with sufficient privileges. On modern macOS
      versions, you may need to disable SIP or run as root to read TCC.db.

    EXAMPLES:
      1) \(programName)
         # Parse TCC from the current user's database

      2) \(programName) -p /Library/Application\\ Support/com.apple.TCC/TCC.db
         # Parse system-wide TCC (requires root or SIP disabled)

    """
    print(usage)
}

/// Highlights interesting records for a pentester
/// E.g., services that often indicate powerful permissions or potential data leak vectors
func highlightInterestingServices(_ record: TCCRecord) -> Bool {
    // Common high-impact TCC services a pentester might want to focus on:
    // - kTCCServiceAccessibility
    // - kTCCServiceScreenCapture
    // - kTCCServiceSystemPolicyAllFiles (Full Disk Access)
    // - kTCCServiceAppleEvents
    // - kTCCServiceMicrophone
    // - kTCCServiceCamera
    // - kTCCServiceCalendar / kTCCServiceReminders / kTCCServiceContacts
    // Expand or customize as needed.
    
    let interestingServices = [
        "kTCCServiceAccessibility",
        "kTCCServiceScreenCapture",
        "kTCCServiceSystemPolicyAllFiles",
        "kTCCServiceAppleEvents",
        "kTCCServiceMicrophone",
        "kTCCServiceCamera",
        "kTCCServiceCalendar",
        "kTCCServiceReminders",
        "kTCCServiceContacts"
    ]
    
    return interestingServices.contains(record.service)
}

/// Prints a structured table of TCC records, highlighting interesting entries
func printTCCRecords(_ records: [TCCRecord]) {
    // Sort records by service for easier grouping
    let sorted = records.sorted { $0.service < $1.service }
    
    // Print header
    let header = String(
        format: "%-30s %-40s %-10s %-10s %-20s %-30s",
        "SERVICE", "CLIENT", "AUTH", "PROMPTS", "LAST_MODIFIED", "SANDBOX_ID"
    )
    print(header)
    print(String(repeating: "-", count: header.count))
    
    for record in sorted {
        let line = String(
            format: "%-30s %-40s %-10s %-10d %-20s %-30s",
            record.service,
            record.client,
            record.authDescription,
            record.promptCount,
            record.lastModifiedDateString,
            record.sandboxId
        )
        
        // If a service is "interesting" from a pentester perspective, prefix with an asterisk
        if highlightInterestingServices(record) {
            print("* " + line)
        } else {
            print("  " + line)
        }
    }
}

// MARK: - Main Entry Point

func main() {
    let args = CommandLine.arguments
    let programName = (args.first as NSString?)?.lastPathComponent ?? "TCCParser"
    
    // Default path for user-level TCC
    var tccPath = NSHomeDirectory() + "/Library/Application Support/com.apple.TCC/TCC.db"
    
    // Simple arg parse: check for -h/--help, -p/--path
    var i = 1
    while i < args.count {
        let arg = args[i]
        if arg == "-h" || arg == "--help" {
            printHelp(programName: programName)
            exit(0)
        } else if arg == "-p" || arg == "--path" {
            if i + 1 < args.count {
                tccPath = args[i + 1]
                i += 1
            } else {
                fputs("[-] ERROR: Missing path after '\(arg)'\n", stderr)
                exit(1)
            }
        } else {
            fputs("[-] ERROR: Unknown option '\(arg)'\n", stderr)
            printHelp(programName: programName)
            exit(1)
        }
        i += 1
    }
    
    // Check if file exists
    guard FileManager.default.fileExists(atPath: tccPath) else {
        fputs("[-] ERROR: No TCC database found at path: \(tccPath)\n", stderr)
        exit(1)
    }
    
    let records = parseTCCDatabase(atPath: tccPath)
    if records.isEmpty {
        print("[*] No records found or unable to read TCC. Possibly insufficient privileges?")
        exit(0)
    }
    
    // Print all records
    print("[+] TCC records found: \(records.count)")
    printTCCRecords(records)
}

main()

