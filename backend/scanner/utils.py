import subprocess

def run_nmap_scan(target, scan_type):
    try:
        # Define different scan types
        scan_modes = {
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
        command = scan_modes.get(scan_type, ["nmap", target])

        # Run command
        result = subprocess.check_output(
            command,
            stderr=subprocess.STDOUT,
            text=True
        )

        return result

    except subprocess.CalledProcessError as e:
        return f"Nmap execution error:\n{e.output}"
