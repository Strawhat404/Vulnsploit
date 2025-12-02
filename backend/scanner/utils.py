import subprocess

def run_scan(target, scan_type):
    try:
        if scan_type == "nikto":
            command = ["nikto", "-h", target]
        elif scan_type == "sqlmap":
            command = ["sqlmap", "-u", target, "--batch"]
        elif scan_type == "subfinder":
            command = ["subfinder", "-d", target, "-silent"]

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

        return result

    except subprocess.CalledProcessError as e:
        return f"Scan execution error:\n{e.output}"
    except Exception as e:
        return f"An unexpected error occurred:{str(e)}"
