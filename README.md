# Penetration-Testing-Toolkit

*COMPANY*: CODTECH IT SOLUTION

*NAME*: SUKHDEEP SINGH

*INTERN ID*: CT04DK913

*DOMAIN*: CYBER SECURITY & ETHICAL HACKER

*DURATION*: 4 WEEKS

*MENTOR*: NEELA SANTOSH

DESCRIPTION

# 🔍 Penetration Testing Toolkit

The Penetration Testing Toolkit is a Python-based graphical application built for penetration testers, cybersecurity enthusiasts, and network administrators who require a robust and visually engaging interface to carry out common pentesting operations. Developed with tkinter and ttkbootstrap, this application wraps several security-focused utilities into an intuitive, multi-tabbed interface with colored sections, dynamic progress feedback, and session-saving capabilities.

# 🌟 Key Features

**1. Colorful Tabbed GUI Interface**

The GUI leverages the ttkbootstrap theming engine to provide a visually appealing, colorful, and modern layout. Each tab is uniquely styled:

- Primary tab (blue) for port scanning
- Warning tab (orange) for SSH brute-forcing
- Success tab (green) for WHOIS lookups
- Danger tab (red) for directory brute-forcing

These colors not only improve aesthetics but also enhance usability by visually segmenting different tools and operations.

**2. Port Scanning Utility**

This module allows users to scan a target IP address for open ports in the range of 20–1024. It uses multi-threaded socket connections to test each port and outputs results in real-time within a scrollable text box. Upon completion, it generates a graphical heatmap using matplotlib, giving the user a visual summary of which ports are open.

**3. SSH Brute Forcer**

Designed for use on systems where SSH login attempts are permitted, this tool asks for:

- A target IP/domain
- SSH username
- A password wordlist

The application attempts to log in using each password until it succeeds or exhausts the list. A progress bar indicates how much of the list has been tried, and successful or failed attempts are clearly logged.

**4. WHOIS Lookup Tool**

This feature performs a WHOIS query for a given domain, retrieving registration data such as domain creation date, expiration, registrar details, and more. This is especially useful in reconnaissance phases during security audits. If the WHOIS module is unavailable, the app gracefully notifies the user.

**5. Directory Brute Forcing**

For web application testing, the tool performs directory enumeration using a provided wordlist. Each word is appended to the URL, and a GET request is made. If a valid response is received (typically HTTP 200 OK), it logs the accessible path. This can help identify hidden resources or unprotected endpoints on web servers.

**6. Dynamic Progress Bars**

Each module is equipped with a visual progress bar. Whether scanning ports, iterating over a wordlist, or brute-forcing directories, the application gives a live indication of how far along the task is, improving user feedback and responsiveness.

**7. Save/Load Session Support**

Users can save their current session to a JSON file and reload it later. This includes:

- Target IP or URL
- SSH credentials and wordlist paths
- Directory brute-force wordlist

This is ideal for professionals working on recurring engagements or who need to pause and resume testing.

# 🛠 Technical Stack

- Python 3
- Tkinter / ttkbootstrap for GUI
- Socket for network port scanning
- Paramiko for SSH interactions
- Requests for web enumeration
- Matplotlib for port scan heatmap
- Whois module for domain registration info

# 💡 Use Cases

Cybersecurity training and practice

- Internal network testing
- Red team assessments
- Educational demonstrations
- Bug bounty reconnaissance

# 🔐 Ethical Use Notice

This tool is intended for educational and authorized security testing only. Unauthorized use against systems without explicit permission is illegal and unethical.

# Output

**Port Scanner**
![Image](https://github.com/user-attachments/assets/88a674a4-bd9a-4b3f-8b00-ab99cb5fef18)

**Port Scanning**
![Image](https://github.com/user-attachments/assets/5d4c98e9-9e55-41f0-b546-5442f963d33b)

**SSH Brute Force**
![Image](https://github.com/user-attachments/assets/7b7538cd-52a2-4c90-88a7-950f60bc662f)

**WHOIS Lookup**
![Image](https://github.com/user-attachments/assets/be457a28-bf30-4247-b4a4-272d35427565)

**Directory Brute Force**
![Image](https://github.com/user-attachments/assets/b4367010-9f6d-4269-af07-51062a89c540)
