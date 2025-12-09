import subprocess
import json

def run_scan(target, scan_type):
    try:
        if scan_type == "nikto":
            command = ["nikto", "-h", target]
        elif scan_type == "sqlmap":
            command = ["sqlmap", "-u", target,
                "--batch",
                "--forms",
                "--crawl=2",
                "--smart",
                "--random-agent",
                "--level=1",
                "--risk=1"
            ]
        elif scan_type == "subfinder":
            command = ["subfinder", "-d", target, "-silent"]
        elif scan_type == "whatweb":
            command = ["whatweb", target, "--no-errors", "--color=never"]
        elif scan_type == "gobuster":
            command = ["gobuster", "dir", "-u", target, "-w", "/usr/share/wordlists/common.txt", "--no-error"]
        elif scan_type == "nuclei":
            command = ["nuclei", "-u", target, "-silent", "-jsonl"]
        elif scan_type == "wpscan":
            command = ["wpscan", "--url", target, "--no-update", "--format", "json", "--disable-tls-checks",]

        else:

        # Define different scan types
            nmap_modes = {
                "quick": ["nmap", "-T4", "-F", target],
                "full": ["nmap", "-sV", "-p-", target],
                "os_detection": ["nmap", "-O", target],
                "aggressive": ["nmap", "-A", target],
                "udp": ["nmap", "-sU", target],
                "ping_sweep": ["nmap", "-sn", target],
                "service_version": ["nmap", "-sV", target],
                "stealth": ["nmap", "-sS", target],
                "vuln": ["nmap", "--script", "vuln", target],
            }

        # Default command if unknown scan type
            command = nmap_modes.get(scan_type, ["nmap", target])

        # Run command
        result = subprocess.check_output(
            command,
            stderr=subprocess.STDOUT,
            text=True
            )

            json_result == None

            if scan_type = "nuclei":

                #Nuclie returns JSON lines so we need to parse it
                json_result = [json.loads(line) for line in result.splitlines() if line.strip()]

            elif scan_type = "wpscan":

                #wpscan returns one big JSON object
                try:
                    json_result = json.loads(result)
                except json.JSONDecodeError:
                    pass  #fallback if it's not valid json

            return result, json_result  #<--- Return BOTH

    except subprocess.CalledProcessError as e:
        return f"Scan execution error:\n{e.output}"
    except Exception as e:
        return f"An unexpected error occurred:{str(e)}"
