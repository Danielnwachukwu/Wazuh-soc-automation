# Wazuh SOC Automation

This project demonstrates a Security Operations Center (SOC) automation script that parses Wazuh SIEM alerts and classifies security events based on attack type and severity level.

The script reads security events from:

/var/ossec/logs/alerts/alerts.json

and outputs SOC-style alerts in real time.

---

## Features

- Real-time monitoring of Wazuh alerts
- Attack classification
- Risk severity classification (LOW / MEDIUM / HIGH / CRITICAL)
- SOC-style alert output

---

## Lab Environment

The project was tested in a cybersecurity lab environment consisting of:

Kali Linux (Attacker)
        ↓
Ubuntu Server (Wazuh Agent)
        ↓
Wazuh Manager (SIEM)
        ↓
alerts.json
        ↓
Python SOC Automation Script

---

## 

[HIGH][SSH Brute Force]
Agent: ubuntu-agent
Rule: 5716
Level: 10

[HIGH][Privilege Escalation]
Agent: wazuh-server
Rule: 100500

[LOW][Security Policy Violation]
Agent: PYTHON001


---

## Tools Used

- Wazuh SIEM
- Python
- Linux
- Hydra
- Nmap
- Nikto

---

## How to Run

Clone the repository:

git clone https://github.com/Danielnwachukwu/Wazuh-soc-automation.git

Run the script:
sudo python3 log_reader.py

---

## Project Purpose

The goal of this project is to demonstrate how SOC analysts can automate SIEM alert analysis to quickly classify and prioritize security events.

---

## Disclaimer

This project was conducted in an isolated lab environment for educational purposes only.

Example Alert Output
