import psutil

# Common suspicious/keylogger-related keywords
suspicious_keywords = [
    "keylog", "logger", "hook", "keyboard", "spy", "monitor"
]

print("Scanning for suspicious processes...\n")

found = False

for process in psutil.process_iter(['pid', 'name']):
    try:
        pname = process.info['name'].lower()

        for keyword in suspicious_keywords:
            if keyword in pname:
                print(f"[!] Suspicious Process Found")
                print(f"PID : {process.info['pid']}")
                print(f"Name: {process.info['name']}\n")
                found = True

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

if not found:
    print("No suspicious keylogger-related process detected.")
