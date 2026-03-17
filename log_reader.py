
import json
import time
from collections import defaultdict

LOG_FILE = "/var/ossec/logs/alerts/alerts.json"

# -----------------------------
# ANSI Colors (SIEM-style)
# -----------------------------
RESET = "\033[0m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
ORANGE = "\033[91m"
RED = "\033[31m"
CYAN = "\033[96m"


# -----------------------------
# Track brute force attempts
# -----------------------------
failed_attempts = defaultdict(int)


# -----------------------------
# Attack Classification
# -----------------------------
def classify_attack(rule_id, description):

    description = description.lower()

    if rule_id in [5716, 5503, 5710]:
        return "SSH Brute Force / Invalid User"

    elif rule_id == 5715:
        return "Successful SSH Login / Lateral Movement"

    elif rule_id in [5402, 100500]:
        return "Privilege Escalation"

    elif rule_id == 5501:
        return "PAM Login Event"

    elif rule_id == 52002:
        return "Security Policy Violation (AppArmor)"

    elif "sql" in description:
        return "SQL Injection Attack"

    elif "nikto" in description:
        return "Nikto Web Scan"

    elif "smtp" in description:
        return "SMTP Enumeration"

    elif "snmp" in description:
        return "SNMP Enumeration"

    elif "telnet" in description:
        return "Telnet Attack"

    elif "scan" in description or "nmap" in description:
        return "Port Scanning"

    elif "http" in description or "apache" in description:
        return "Web Server Attack"

    else:
        return "Unknown Activity"


# -----------------------------
# Risk Classification
# -----------------------------
def classify_risk(level):

    level = int(level)

    if level <= 3:
        return "LOW"

    elif level <= 7:
        return "MEDIUM"

    elif level <= 12:
        return "HIGH"

    else:
        return "CRITICAL"


# -----------------------------
# Risk Color
# -----------------------------
def risk_color(risk):

    if risk == "LOW":
        return GREEN

    elif risk == "MEDIUM":
        return YELLOW

    elif risk == "HIGH":
        return ORANGE

    else:
        return RED


# -----------------------------
# Monitor Alerts
# -----------------------------
def monitor_alerts():

    print(CYAN + "\n====================================")
    print("SOC Alert Monitor Started")
    print("Monitoring:", LOG_FILE)
    print("Press CTRL+C to stop")
    print("====================================\n" + RESET)

    with open(LOG_FILE, "r") as f:

        # Move to end like tail -f
        f.seek(0, 2)

        while True:

            line = f.readline()

            if not line:
                time.sleep(0.5)
                continue

            try:

                alert = json.loads(line)

                rule = alert.get("rule", {})
                agent = alert.get("agent", {})

                rule_id = int(rule.get("id", 0))
                level = int(rule.get("level", 0))
                description = rule.get("description", "No description")

                agent_name = agent.get("name", "Unknown")
                timestamp = alert.get("timestamp", "N/A")
                src_ip = alert.get("srcip", "N/A")

                attack_type = classify_attack(rule_id, description)
                risk = classify_risk(level)

                color = risk_color(risk)

                # -----------------------------
                # Brute Force Detection
                # -----------------------------
                if rule_id in [5716, 5503, 5710] and src_ip != "N/A":

                    failed_attempts[src_ip] += 1

                    if failed_attempts[src_ip] >= 3:

                        print(RED + "\n🚨 CRITICAL ALERT - SSH BRUTE FORCE DETECTED 🚨")
                        print(f"Attacker IP: {src_ip}")
                        print(f"Attempts: {failed_attempts[src_ip]}")
                        print("MITRE ATT&CK: T1110 (Brute Force)")
                        print("====================================\n" + RESET)

                # -----------------------------
                # Print Alert
                # -----------------------------
                print(color + "\n====================================")
                print(f"Risk: {risk}")
                print(f"Attack Type: {attack_type}")
                print(f"Time: {timestamp}")
                print(f"Agent: {agent_name}")
                print(f"Source IP: {src_ip}")
                print(f"Rule ID: {rule_id}")
                print(f"Level: {level}")
                print(f"Description: {description}")
                print("====================================" + RESET)

            except json.JSONDecodeError:
                continue


# -----------------------------
# Main
# -----------------------------
if __name__ == "__main__":
    monitor_alerts()
