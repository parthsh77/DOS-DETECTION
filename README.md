# DOS Attack Detection System

The **DOS Attack Detection System** is a CLI-based Python project designed to identify and analyze malicious Denial-of-Service (DOS) attacks in real time. It monitors network traffic patterns, detects anomalies such as sudden spikes in requests, and blocks suspicious IPs using system firewalls. This tool is beginner-friendly and works on both Linux and Windows systems.

---

## Table of Contents
- [Prerequisites](#prerequisites)
- [Setup and Usage](#setup-and-usage)
- [Example Workflow](#example-workflow)
- [Optional Enhancements](#optional-enhancements)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

Before using the DOS Attack Detection System, ensure the following:

1. **Python Installation**:
   - Python 3.x must be installed on your system. Download it from the official website: [python.org](https://www.python.org/).

2. **Operating System**:
   - The script is compatible with **Linux** and **Windows**.

3. **Administrative Privileges**:
   - The script requires administrative privileges to monitor network traffic and block IPs.
   - On Linux, run the script with `sudo`.
   - On Windows, run the script as Administrator.

4. **Required Python Libraries**:
   - Install the required libraries using pip:
     ```bash
     pip install scapy pandas matplotlib
     ```

5. **Linux (Optional)**:
   - Ensure `iptables` is installed (usually pre-installed on most Linux distributions).
   - If not, install it using:
     ```bash
     sudo apt-get install iptables
     ```

6. **Windows (Optional)**:
   - Windows Firewall API is used for blocking IPs (not fully implemented in this version).
   - You can manually block IPs using the Windows Firewall GUI or `netsh` command.

---

## Setup and Usage

1. **Save the Script**:
   - Copy the provided Python code into a file named `dosdetection.py`.

2. **Run the Script**:
   - Open a terminal or command prompt.
   - Navigate to the directory where the script is saved.
   - Run the script:
     - On Linux:
       ```bash
       sudo python3 dosdetection.py
       ```
     - On Windows:
       - Open Command Prompt as Administrator.
       ```bash
       python dosDetection.py
       ```

3. **Monitor Network Traffic**:
   - The script will start monitoring network traffic in real time.
   - It will detect anomalies such as sudden spikes in requests and block suspicious IPs.

4. **Logs**:
   - Detected attacks are logged in `dos_log.csv` in the same directory as the script.
   - Example log entry:
     ```
     timestamp,ip,requests
     2025-02-09 14:30:45,192.168.1.100,105
     ```

---

## Example Workflow

1. **Simulate a DOS Attack**:
   - Use a tool like **hping3** or **LOIC** to simulate a DOS attack.
   - Example using hping3:
     ```bash
     hping3 -c 1000 -d 120 -S -w 64 -p 80 --flood --rand-source target_ip
     ```

2. **Run the Detection System**:
   - Start the DOS detection system:
     ```bash
     sudo python3 dosdetection.py
     ```

3. **Detect and Block**:
   - The script will detect the attack, block the IP, and log the event.

---

## Optional Enhancements

1. **AI-Driven Anomaly Detection**:
   - Use machine learning models (e.g., Isolation Forest, SVM) to detect anomalies in traffic patterns.
   - Train the model on historical network data.

2. **Rate Limiting**:
   - Implement rate limiting for specific IPs or protocols.

3. **Visualization**:
   - Use Matplotlib to visualize traffic patterns and detected anomalies.

4. **Email Alerts**:
   - Send email notifications when a DOS attack is detected.

5. **Cross-Platform Blocking**:
   - Implement IP blocking for Windows using the `netsh` command or Windows Firewall API.

---

## Troubleshooting

1. **Permission Denied**:
   - Ensure you are running the script with administrative privileges.
   - On Linux, use `sudo`.
   - On Windows, run Command Prompt as Administrator.

2. **Scapy Permission Issues**:
   - On Linux, ensure you have the necessary permissions to capture packets.
   - Run the script with `sudo`.

3. **Windows Firewall Blocking**:
   - If IP blocking is not working on Windows, manually block the IP using the Windows Firewall GUI or `netsh` command.

4. **Dependencies Not Found**:
   - Ensure all required libraries are installed:
     ```bash
     pip install scapy pandas matplotlib
     ```

---


## Acknowledgments
- Built using [Scapy](https://scapy.net/) for network packet analysis.
- Inspired by real-world DOS attack mitigation techniques.

---

## Support
For any issues or questions, please open an issue on the [GitHub repository](https://github.com/your-username/DOS-DETECTION/issues).
