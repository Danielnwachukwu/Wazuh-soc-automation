# Wazuh SOC Automation

This project demonstrates a SOC automation script that parses Wazuh SIEM alerts and classifies security events based on attack type and severity level.

The script reads security events from:

/var/ossec/logs/alerts/alerts.json

and outputs SOC-style alerts in real time.

## Features

• Real-time Wazuh alert monitoring  
• Attack classification  
• Risk severity classification (LOW / MEDIUM / HIGH / CRITICAL)  
• SOC-style console output  

## Lab Architecture

Kali Linux (Attacker)
        ↓
Ubuntu Server (Wazuh Agent)
        ↓
Wazuh SIEM Manager
        ↓
alerts.json
        ↓
Python SOC Automation Script

## Example Output

[HIGH][SSH Brute Force]
Agent: ubuntu-agent
Rule: 5716
Level: 10

[HIGH][Privilege Escalation]
Agent: wazuh-server
Rule: 100500
Level: 10

[LOW][Security Policy Violation]
Agent: PYTHON001
Rule: 52002

## Tools Used

- Wazuh SIEM
- Python
- wireshark
- Linux
- Hydra
- Nmap
- Nikto


## Disclaimer

This project was conducted in an isolated cybersecurity lab environment for educational purposes.

## Running the Script
