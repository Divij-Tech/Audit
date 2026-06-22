"""
╔══════════════════════════════════════════════════════════════╗
║         SecureCheck — Local Security Audit Dashboard         ║
║         For personal/educational use only                    ║
║         Author: [Your Name] | GitHub: [your-username]        ║
╚══════════════════════════════════════════════════════════════╝

WHAT THIS TOOL DOES:
  - Checks password strength against common rules
  - Scans a folder for suspicious file names/extensions
  - Reminds you about weak system security settings
  - Shows basic network info for YOUR own device
  - Generates a report (console + saved CSV)

WHAT THIS TOOL DOES NOT DO:
  - Scan other people's devices (illegal without permission)
  - Exploit any vulnerability
  - Collect or send any data anywhere
"""

import os
import sys
import re
import csv
import socket
import platform
import datetime
import getpass
import ipaddress
from pathlib import Path


# ─────────────────────────────────────────────
#  ANSI COLOR CODES  (makes the terminal pretty)
# ─────────────────────────────────────────────
class Color:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    DIM    = "\033[2m"

def c(color: str, text: str) -> str:
    """Wrap text in a color code, then reset."""
    return f"{color}{text}{Color.RESET}"


# ─────────────────────────────────────────────
#  REPORT STORAGE  (collected across all checks)
# ─────────────────────────────────────────────
report_rows: list[dict] = []   # Each row = one finding

def add_finding(category: str, status: str, detail: str):
    """Add a finding to the global report list."""
    report_rows.append({
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "category":  category,
        "status":    status,   # PASS / WARN / FAIL / INFO
        "detail":    detail,
    })


# ─────────────────────────────────────────────
#  BANNER & MENU
# ─────────────────────────────────────────────
def print_banner():
    """Print the ASCII art header."""
    print(c(Color.CYAN, Color.BOLD + """
╔══════════════════════════════════════════════════════════════╗
║      🔒  SecureCheck — Local Security Audit Dashboard  🔒    ║
║         For personal & educational use only                  ║
╚══════════════════════════════════════════════════════════════╝"""))


def print_menu():
    """Display the main menu options."""
    print(c(Color.WHITE, """
  ┌──────────────────────────────────┐
  │  [1]  Password Strength Checker  │
  │  [2]  Suspicious File Scanner    │
  │  [3]  System Security Reminders  │
  │  [4]  Network Info (Your Device) │
  │  [5]  Run ALL Checks             │
  │  [6]  Save Report to CSV         │
  │  [0]  Exit                       │
  └──────────────────────────────────┘"""))


# ─────────────────────────────────────────────
#  MODULE 1 — PASSWORD STRENGTH CHECKER
# ─────────────────────────────────────────────

# Common weak passwords — a short blocklist to catch obvious choices
COMMON_PASSWORDS = {
    "password", "123456", "password1", "qwerty", "letmein",
    "admin", "welcome", "monkey", "dragon", "master", "iloveyou",
    "abc123", "1234567890", "passw0rd", "sunshine", "princess",
}

def check_password_strength(password: str) -> dict:
    """
    Evaluate a password against several security rules.

    Returns a dict with:
      - score      : 0–5 (5 = strongest)
      - rating     : human-readable label
      - issues     : list of failing checks
      - passed     : list of passing checks
    """
    issues  = []
    passed  = []
    score   = 0

    # Rule 1: Minimum length
    if len(password) >= 12:
        score += 1
        passed.append("Length ≥ 12 characters")
    else:
        issues.append(f"Too short ({len(password)} chars) — use 12 or more")

    # Rule 2: Uppercase letter
    if re.search(r"[A-Z]", password):
        score += 1
        passed.append("Contains uppercase letter")
    else:
        issues.append("No uppercase letters (A–Z)")

    # Rule 3: Lowercase letter
    if re.search(r"[a-z]", password):
        score += 1
        passed.append("Contains lowercase letter")
    else:
        issues.append("No lowercase letters (a–z)")

    # Rule 4: Digits
    if re.search(r"\d", password):
        score += 1
        passed.append("Contains a number (0–9)")
    else:
        issues.append("No numbers")

    # Rule 5: Special characters
    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
        score += 1
        passed.append("Contains a special character")
    else:
        issues.append("No special characters (!@#$...)")

    # Blocklist override — even a high-scoring password can be common
    if password.lower() in COMMON_PASSWORDS:
        score = 0
        issues.append("⚠  This is a KNOWN common password — never use it")

    # Translate score to a label
    if score == 5:
        rating = "Strong 💪"
    elif score >= 3:
        rating = "Moderate ⚠"
    else:
        rating = "Weak ❌"

    return {"score": score, "rating": rating, "issues": issues, "passed": passed}


def run_password_checker():
    """Interactive password strength check (password is never stored/logged)."""
    print(c(Color.CYAN, "\n── Password Strength Checker ──────────────────"))
    print(c(Color.DIM,  "  Your password is checked locally and never saved.\n"))

    # getpass hides typing in the terminal (like a real password prompt)
    try:
        password = getpass.getpass("  Enter a password to test: ")
    except (KeyboardInterrupt, EOFError):
        print("\n  Cancelled.")
        return

    if not password:
        print(c(Color.YELLOW, "  No input received."))
        return

    result = check_password_strength(password)

    # Pick a display color based on rating
    rating_color = (
        Color.GREEN  if result["score"] == 5 else
        Color.YELLOW if result["score"] >= 3 else
        Color.RED
    )

    print(f"\n  Rating : {c(rating_color, result['rating'])}")
    print(f"  Score  : {result['score']}/5\n")

    for item in result["passed"]:
        print(c(Color.GREEN,  f"  ✔  {item}"))
    for item in result["issues"]:
        print(c(Color.RED,    f"  ✘  {item}"))

    # Log to report (we never log the actual password — only the result)
    add_finding("Password", result["rating"], f"Score {result['score']}/5 | Issues: {len(result['issues'])}")
    print()


# ─────────────────────────────────────────────
#  MODULE 2 — SUSPICIOUS FILE SCANNER
# ─────────────────────────────────────────────

# Extensions often associated with malware or data exfiltration
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".vbs", ".ps1", ".sh",   # Executables/scripts
    ".scr", ".pif", ".com",                           # Old-style Windows threats
    ".jar", ".js", ".jse",                            # Scripting
    ".hta", ".msi", ".dll",                           # System/install
    ".docm", ".xlsm", ".pptm",                        # Macro-enabled Office
    ".iso", ".img",                                    # Disk images
    ".lnk",                                           # Shortcut (often used in attacks)
}

# Regex patterns for suspicious file-name patterns
SUSPICIOUS_NAME_PATTERNS = [
    (r"invoice.*\.(exe|bat|cmd)",  "Fake invoice executable"),
    (r"password[s]?\.",            "File named 'passwords'"),
    (r"\.exe\.pdf$",               "Double extension disguise (.exe.pdf)"),
    (r"\.pdf\.exe$",               "Double extension disguise (.pdf.exe)"),
    (r"^~\$",                      "Temp Office lock file"),
    (r"crack|keygen|patch",        "Software crack/keygen keyword"),
    (r"free.*download",            "Suspicious download name"),
]


def scan_folder(folder_path: str) -> list[dict]:
    """
    Walk a directory tree and return a list of suspicious findings.
    Only reads file names — never opens or executes anything.
    """
    findings = []
    path = Path(folder_path)

    if not path.exists():
        print(c(Color.RED, f"\n  ✘ Folder not found: {folder_path}"))
        return findings

    if not path.is_dir():
        print(c(Color.RED, f"\n  ✘ Not a directory: {folder_path}"))
        return findings

    # os.walk() visits every subfolder recursively
    for root, dirs, files in os.walk(path):
        # Skip hidden directories (e.g., .git) to reduce noise
        dirs[:] = [d for d in dirs if not d.startswith(".")]

        for filename in files:
            full_path = Path(root) / filename
            ext       = full_path.suffix.lower()
            reason    = None

            # Check 1 — extension in the suspicious set
            if ext in SUSPICIOUS_EXTENSIONS:
                reason = f"Suspicious extension: {ext}"

            # Check 2 — name matches a known bad pattern
            for pattern, label in SUSPICIOUS_NAME_PATTERNS:
                if re.search(pattern, filename, re.IGNORECASE):
                    reason = label
                    break

            if reason:
                findings.append({
                    "file":   str(full_path),
                    "reason": reason,
                })

    return findings


def run_file_scanner():
    """Prompt user for a folder path, scan it, and display results."""
    print(c(Color.CYAN, "\n── Suspicious File Scanner ─────────────────────"))
    print(c(Color.DIM,  "  Only reads file names — never opens files.\n"))

    # Default to Desktop or home directory
    default = str(Path.home() / "Desktop")
    folder  = input(f"  Enter folder path to scan [{default}]: ").strip()
    if not folder:
        folder = default

    print(c(Color.DIM, f"\n  Scanning: {folder} ...\n"))

    findings = scan_folder(folder)

    if not findings:
        print(c(Color.GREEN, "  ✔  No suspicious files found in that folder."))
        add_finding("File Scan", "PASS", f"No issues in {folder}")
    else:
        print(c(Color.YELLOW, f"  ⚠  Found {len(findings)} suspicious item(s):\n"))
        for f in findings:
            print(c(Color.RED,    f"  ✘  {f['reason']}"))
            print(c(Color.DIM,    f"     {f['file']}\n"))
            add_finding("File Scan", "WARN", f"{f['reason']} — {f['file']}")

    print()


# ─────────────────────────────────────────────
#  MODULE 3 — SYSTEM SECURITY REMINDERS
# ─────────────────────────────────────────────

def check_os_info() -> dict:
    """Gather basic OS details using the standard library."""
    return {
        "os":      platform.system(),          # 'Windows', 'Linux', 'Darwin'
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "user":    getpass.getuser(),
    }


def run_security_reminders():
    """
    Display a checklist of security best practices.
    These are reminders — we can't automatically fix them for you,
    but we can tell you exactly what to look for.
    """
    print(c(Color.CYAN, "\n── System Security Reminders ───────────────────"))
    os_info = check_os_info()

    print(c(Color.WHITE, f"\n  OS      : {os_info['os']} {os_info['release']}"))
    print(c(Color.WHITE, f"  Version : {os_info['version'][:60]}"))
    print(c(Color.WHITE, f"  User    : {os_info['user']}\n"))

    # Generic reminders that apply on all platforms
    reminders = [
        ("Keep your OS updated",          "Run Windows Update / apt upgrade / Software Update regularly"),
        ("Use a password manager",        "Never reuse passwords. Try Bitwarden (free & open source)"),
        ("Enable 2FA everywhere",         "Use an authenticator app, not SMS, for critical accounts"),
        ("Lock screen when away",         "Set auto-lock to 5 minutes or less"),
        ("Use a firewall",                "Enable the built-in firewall on your OS"),
        ("Avoid public Wi-Fi for banking","Or use a trusted VPN if you must"),
        ("Back up your data",             "Follow the 3-2-1 rule: 3 copies, 2 media types, 1 offsite"),
        ("Check app permissions",         "Remove apps you no longer use; review camera/mic access"),
    ]

    # Platform-specific extras
    if os_info["os"] == "Windows":
        reminders += [
            ("Enable Windows Defender",   "Settings → Windows Security → Virus & threat protection"),
            ("Disable auto-run",          "Prevents malware from running off USB drives automatically"),
            ("Check startup programs",    "Task Manager → Startup tab — disable anything unfamiliar"),
        ]
    elif os_info["os"] == "Darwin":  # macOS
        reminders += [
            ("Enable FileVault",          "System Preferences → Security & Privacy → FileVault"),
            ("Enable Gatekeeper",         "Only allow apps from the App Store or identified developers"),
            ("Review Login Items",        "System Preferences → Users & Groups → Login Items"),
        ]
    elif os_info["os"] == "Linux":
        reminders += [
            ("Enable UFW firewall",       "Run: sudo ufw enable"),
            ("Audit sudo access",         "Run: sudo cat /etc/sudoers"),
            ("Check open ports",          "Run: ss -tuln  (or netstat -tuln)"),
        ]

    print(c(Color.WHITE, "  Security Checklist:\n"))
    for i, (title, detail) in enumerate(reminders, 1):
        print(c(Color.YELLOW, f"  [{i:02}] {title}"))
        print(c(Color.DIM,    f"       → {detail}\n"))
        add_finding("System Reminder", "INFO", f"{title}: {detail}")


# ─────────────────────────────────────────────
#  MODULE 4 — NETWORK INFO (YOUR DEVICE ONLY)
# ─────────────────────────────────────────────

def get_network_info() -> dict:
    """
    Collect basic network info for the local machine only.
    Uses socket and ipaddress from the standard library.
    Does NOT scan any external hosts or other devices.
    """
    info = {
        "hostname":    "Unknown",
        "local_ip":    "Unknown",
        "is_private":  None,
        "fqdn":        "Unknown",
    }

    try:
        # gethostname() returns the machine's own name
        hostname = socket.gethostname()
        info["hostname"] = hostname

        # getfqdn() tries to resolve the fully-qualified domain name
        info["fqdn"] = socket.getfqdn()

        # Connect to a known address to find which local IP we're using
        # Note: no data is actually sent — connect() on UDP doesn't handshake
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))   # Google DNS — just used for routing lookup
            local_ip = s.getsockname()[0]

        info["local_ip"] = local_ip

        # ipaddress module tells us if the IP is private (192.168.x.x etc.)
        ip_obj = ipaddress.ip_address(local_ip)
        info["is_private"] = ip_obj.is_private

    except (socket.error, OSError) as e:
        # Network might be unavailable — handle gracefully
        info["error"] = str(e)

    return info


def run_network_info():
    """Display local network information for the user's own device."""
    print(c(Color.CYAN, "\n── Network Info (Your Device Only) ─────────────"))
    print(c(Color.DIM,  "  No scanning of external hosts or other devices.\n"))

    info = get_network_info()

    if "error" in info:
        print(c(Color.RED, f"  ✘ Could not retrieve network info: {info['error']}"))
        add_finding("Network", "FAIL", info["error"])
        return

    print(c(Color.WHITE, f"  Hostname   : {info['hostname']}"))
    print(c(Color.WHITE, f"  FQDN       : {info['fqdn']}"))
    print(c(Color.WHITE, f"  Local IP   : {info['local_ip']}"))

    # Flag if the IP is unexpectedly public
    if info["is_private"]:
        print(c(Color.GREEN, "  IP Type    : Private ✔ (normal for home/office)"))
        add_finding("Network", "PASS", f"Private IP {info['local_ip']} — expected")
    else:
        print(c(Color.RED,   "  IP Type    : PUBLIC ⚠  (unusual — are you on a VPN without NAT?)"))
        add_finding("Network", "WARN", f"Public-facing IP detected: {info['local_ip']}")

    print()

    # Security note about what they should look for themselves
    print(c(Color.YELLOW, "  💡 Tips for checking your own network security:"))
    tips = [
        "Log in to your router admin panel (usually 192.168.1.1 or 192.168.0.1)",
        "Change your router's default admin password if you haven't already",
        "Use WPA3 or WPA2 encryption — never WEP or open Wi-Fi",
        "Disable WPS (Wi-Fi Protected Setup) — it has known vulnerabilities",
        "Check the 'connected devices' list for anything you don't recognise",
    ]
    for tip in tips:
        print(c(Color.DIM, f"  • {tip}"))
        add_finding("Network Tips", "INFO", tip)

    print()


# ─────────────────────────────────────────────
#  MODULE 5 — REPORT SAVER
# ─────────────────────────────────────────────

def save_report():
    """
    Save all collected findings to a CSV file in the current directory.
    CSV can be opened in Excel, Google Sheets, or any text editor.
    """
    if not report_rows:
        print(c(Color.YELLOW, "\n  No findings to save yet. Run some checks first.\n"))
        return

    # Build a filename with the current date-time so reports don't overwrite each other
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = f"securecheck_report_{timestamp}.csv"

    try:
        with open(filename, "w", newline="", encoding="utf-8") as f:
            fieldnames = ["timestamp", "category", "status", "detail"]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(report_rows)

        print(c(Color.GREEN, f"\n  ✔  Report saved → {filename}"))
        print(c(Color.DIM,   f"  {len(report_rows)} finding(s) written.\n"))

    except OSError as e:
        print(c(Color.RED, f"\n  ✘ Could not save report: {e}\n"))


def print_summary():
    """Print a quick summary table of all findings so far."""
    if not report_rows:
        return

    counts = {"PASS": 0, "WARN": 0, "FAIL": 0, "INFO": 0}
    for row in report_rows:
        status = row.get("status", "INFO")
        # Normalize — rating strings like "Strong 💪" map to PASS
        if "strong" in status.lower() or status == "PASS":
            counts["PASS"] += 1
        elif "weak" in status.lower() or status in ("FAIL",):
            counts["FAIL"] += 1
        elif "warn" in status.lower() or status == "WARN" or "moderate" in status.lower():
            counts["WARN"] += 1
        else:
            counts["INFO"] += 1

    print(c(Color.CYAN, "\n── Session Summary ─────────────────────────────"))
    print(c(Color.GREEN,  f"  PASS : {counts['PASS']}"))
    print(c(Color.YELLOW, f"  WARN : {counts['WARN']}"))
    print(c(Color.RED,    f"  FAIL : {counts['FAIL']}"))
    print(c(Color.DIM,    f"  INFO : {counts['INFO']}"))
    print(c(Color.WHITE,  f"  Total findings: {len(report_rows)}\n"))


# ─────────────────────────────────────────────
#  MAIN LOOP
# ─────────────────────────────────────────────

def main():
    """Entry point — runs the menu loop until the user exits."""

    # On Windows, enable ANSI escape codes so colors work
    if platform.system() == "Windows":
        os.system("color")   # Activates ANSI support in cmd.exe

    print_banner()

    while True:
        print_menu()

        try:
            choice = input(c(Color.CYAN, "  → ")).strip()
        except (KeyboardInterrupt, EOFError):
            # Ctrl+C / Ctrl+D exits gracefully
            print(c(Color.YELLOW, "\n\n  Exiting SecureCheck. Stay safe! 🔒\n"))
            break

        if choice == "1":
            run_password_checker()

        elif choice == "2":
            run_file_scanner()

        elif choice == "3":
            run_security_reminders()

        elif choice == "4":
            run_network_info()

        elif choice == "5":
            # Run everything in sequence
            print(c(Color.CYAN, "\n  Running all checks...\n"))
            run_password_checker()
            run_file_scanner()
            run_security_reminders()
            run_network_info()
            print_summary()

        elif choice == "6":
            print_summary()
            save_report()

        elif choice == "0":
            print(c(Color.YELLOW, "\n  Exiting SecureCheck. Stay safe! 🔒\n"))
            break

        else:
            print(c(Color.RED, "\n  Invalid option. Please enter 0–6.\n"))


# ─────────────────────────────────────────────
#  Script entry point
# ─────────────────────────────────────────────
if __name__ == "__main__":
    main()
