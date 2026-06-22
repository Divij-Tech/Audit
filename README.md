# 🔒 SecureCheck — Local Security Audit Dashboard

A beginner-friendly, **100% defensive** personal security audit tool written in Python 3.  
Runs entirely on your own device. No data is sent anywhere.

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)

---

## ✨ Features

| Module | What it does |
|--------|-------------|
| 🔑 **Password Checker** | Scores your password against length, complexity & common-password blocklist |
| 📁 **File Scanner** | Finds suspicious extensions & name patterns in a folder you choose |
| 🛡️ **Security Reminders** | OS-aware checklist of best practices (Windows / macOS / Linux) |
| 🌐 **Network Info** | Shows your device's hostname and local IP — no external scanning |
| 📊 **Report Export** | Saves all findings to a timestamped `.csv` file |

---

## 🚀 How to Run

### Prerequisites
- Python 3.8 or newer (no third-party packages needed — standard library only)

### Steps

```bash
# 1. Clone or download this repo
git clone https://github.com/your-username/securecheck.git
cd securecheck

# 2. Run the tool
python audit.py          # Linux / macOS
python audit.py          # Windows (in PowerShell or cmd)
```

> **Windows tip:** If colors don't show, run `python audit.py` inside **Windows Terminal** instead of the old cmd.exe.

### Quick demo

```
[1]  Password Strength Checker
[2]  Suspicious File Scanner
[3]  System Security Reminders
[4]  Network Info (Your Device)
[5]  Run ALL Checks
[6]  Save Report to CSV
[0]  Exit
```

Pick `[5]` to run everything at once, then `[6]` to save a report.

---

## 📂 Output

Reports are saved to the same folder as `audit.py`:

```
securecheck_report_20250115_143022.csv
```

Open in Excel, Google Sheets, or any text editor.

---

## ⚖️ Legal & Ethical Notice

This tool is designed for **personal, defensive, educational use only**.

- ✅ It reads file names in folders *you* choose
- ✅ It shows network info for *your own device* only
- ❌ It does **not** scan other people's networks or devices
- ❌ It does **not** exploit any vulnerability
- ❌ It does **not** transmit any data

Always obtain explicit permission before running any security tool on a device or network you do not own.

---

## 💡 Suggested Upgrades

These are three features you could add to take the tool further:

### 1. 🔐 Password Breach Check (via Have I Been Pwned API)
Use the [HaveIBeenPwned k-Anonymity API](https://haveibeenpwned.com/API/v3#PwnedPasswords) to check if a password has appeared in known data breaches — without sending the actual password over the network (only the first 5 chars of its SHA-1 hash are sent).

```python
import hashlib, requests

def check_breach(password):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    r = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
    return suffix in r.text  # True = found in breaches
```

### 2. 🗂️ File Hash Checker
Hash every file in a scanned folder and compare against a local known-bad hash list (e.g. from [MalwareBazaar](https://bazaar.abuse.ch/)). Helps detect exact known malware samples.

### 3. 📅 Scheduled Auto-Audit
Use Python's `schedule` library or a system cron job to run all checks automatically (e.g. weekly) and email you the CSV report. Great for building a security habit without thinking about it.

---

## 🗂️ Project Structure

```
securecheck/
├── audit.py      # Main tool (all modules in one file for simplicity)
└── README.md     # This file
```

---

## 📄 License

MIT — free to use, modify, and share. Give credit if you build on it.
