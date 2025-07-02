# Windows Defender Quarantine Retriever 🔐

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![GitHub Issues](https://img.shields.io/github/issues/Cybersecurity-Ethical-Hacker/Windows-Defender-Quarantine-Retriever.svg)](https://github.com/Cybersecurity-Ethical-Hacker/Windows-Defender-Quarantine-Retriever/issues)
[![GitHub Stars](https://img.shields.io/github/stars/Cybersecurity-Ethical-Hacker/Windows-Defender-Quarantine-Retriever.svg)](https://github.com/Cybersecurity-Ethical-Hacker/Windows-Defender-Quarantine-Retriever/stargazers)
[![Contributions Welcome](https://img.shields.io/badge/Contributions-Welcome-brightgreen.svg)](CONTRIBUTING.md)

🔐 Windows Defender Quarantine Retriever is a robust PowerShell tool designed to automate the recovery of quarantined files from Windows Defender. It searches for files based on customizable keywords (defaulting to "lsass"), leverages Defender’s Threat IDs and detection timestamps to pinpoint relevant quarantined items, and retrieves encrypted files from Defender’s quarantine storage. The tool also dynamically locates the Defender quarantine path by checking multiple registry keys with a reliable fallback method. Windows Defender Quarantine Retriever organizes recovered files for streamlined forensic analysis, helping security professionals reclaim vital evidence that might otherwise be inaccessible due to Defender’s automated quarantine processes.

## 📸 Screenshot:
![screenshot](https://github.com/user-attachments/assets/8534d824-4b9f-4b1f-aa61-004a9bb33ede)

## 🛡️ Why it matters:
Sometimes, crucial forensic artifacts or memory dumps (like LSASS process dumps) get quarantined by Windows Defender during investigations. 
This tool helps you safely recover those files for further analysis, preserving vital evidence you might otherwise miss.

## 🚨 Scenario:
A user successfully dumps the LSASS process memory to a file named lsass.dmp within an Active Directory environment. 
Windows Defender automatically quarantines this file, encrypts it, and changes its name, making it tricky to locate and extract manually. 
This tool allows you to locate the quarantined file using the keyword (default: lsass, but customizable if another name used) and recover the exact encrypted file into the \RecoveredResourceData folder. 
From there, you can securely copy it to your Kali Linux system (smbclient, wmiexec.py, evil-winrm, scp) for decryption and further forensic analysis. 

## 🌟 Features

- 🔑 Checks multiple registry keys to accurately locate the Windows Defender quarantine folder, with a fallback to a default path.
- 🔎 Search quarantine path for files matching any keyword (default: lsass).
- 💾 Recover files detected within a customizable time window.
- 📂 Organize recovered files for easy analysis.
- 🛠️ Support quick extraction.

## 🚀 Usage
Windows Defender Quarantine Retriever can be used to recover quarantined files from a single machine or across multiple endpoints when integrated with remote management tools.

📍 Command-Line Options:
```
Powershell usage: .\RecoverDefenderQuarantine.ps1 [options]

options:
  -searchKeyword       Keyword to search in quarantined files (default: "lsass")
  -outputFolder        Directory to save recovered files (default: .\RecoveredResourceData)
  -searchKeyword       Minutes before & after detection to filter files (default: 2)
```

## 💡 Examples
💻 Basic usage: Recover files with default keyword 'lsass' within ±2 minutes of detection:
```powershell
.\RecoverDefenderQuarantine.ps1
```
💻 Search for 'mimikatz' quarantined files within ±5 minutes:
```powershell
.\RecoverDefenderQuarantine.ps1 -searchKeyword "mimikatz" -timeWindowMinutes 5
```
💻 Recover 'ransomware' files into a custom output folder:
```powershell
.\RecoverDefenderQuarantine.ps1 -searchKeyword "ransomware" -outputFolder "C:\Forensics\RecoveredQuarantine"
```


## 📊 Output
- Results are saved in the .\RecoveredResourceData directory, organized into subfolders named by Threat ID and detection timestamp.

## 🐛 Error Handling
- Handles inaccessible or missing registry keys when searching for Defender quarantine path, ignoring errors and continuing.
- Exits the script with an error if creating the output folder fails.
- Exits with error or warning if retrieving Defender threat detections fails or returns no results.
- Exits with error if no valid Defender quarantine path is found via registry or fallback.
- Prints a warning and continues if creation of threat-specific output folders fails.
- Prints a warning and continues if searching the quarantine folder for files fails.
- Prints a warning and continues if no files are found in the specified time window.
- Prints a warning and continues if copying files from quarantine to output folder fails.
- Prints a warning and continues if SHA256 hash calculation of copied files fails.


## 🛠️ Troubleshooting

**Common Issues**

- Ensure you run the script with Administrator privileges otherwise, it may fail to access Windows Defender data or registry keys.
- Defender quarantine folder paths can vary by Windows version and configuration. If the script cannot find the quarantine folder, check the registry keys manually or adjust the fallback path.
- Running the script in restricted environments (e.g., limited user accounts, constrained PowerShell sessions) may cause incomplete results or errors.
- If no threats matching the keyword are found, confirm that Windows Defender has quarantined files with the specified keyword and that the time window parameter covers the detection period.
- For large environments or systems with extensive Defender history, the script might take some time to process all relevant files. Be patient during execution.
- Always run the script in a secure, isolated environment since recovered files can be active malware.


## 📂 Directory Structure
- `RecoverDefenderQuarantine.ps1`: Main Powershell script.

> [!NOTE]
> ⚠️ Caution: Recovered files may be active malware. Always analyze in a secure, isolated environment!

## 🤝 Contributing
Contributions are welcome! Please open an issue or submit a pull request for any improvements, bug fixes, or new features.

## 🛡️ Ethical Usage Guidelines
I am committed to promoting ethical practices in cybersecurity. Please ensure that you use this tool responsibly and in accordance with the following guidelines:

1. Educational Purposes Only
This tool is intended to be used for educational purposes, helping individuals learn about penetration testing techniques and cybersecurity best practices.

2. Authorized Testing
Always obtain explicit permission from the system owner before conducting any penetration tests. Unauthorized testing is illegal and unethical.

3. Responsible Vulnerability Reporting
If you discover any vulnerabilities using this tool, report them responsibly to the respective organizations or maintainers. Do not exploit or disclose vulnerabilities publicly without proper authorization.

4. Compliance with Laws and Regulations
Ensure that your use of this tool complies with all applicable local, national, and international laws and regulations.

## 📚 Learn and Grow
Whether you're a digital forensics analyst, incident responder, or security researcher needing to recover quarantined evidence, Windows Defender Quarantine Retriever is here to support your investigations and ensure no crucial artifact is left behind in your pursuit of clarity and security.

> [!NOTE]
> Let’s build a safer web together! 🌐🔐
