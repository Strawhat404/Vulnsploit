import subprocess

def run_nmap_scan(target, scan_type):
    try:
        if scan_type == "quick":
            command = ["nmap", "-T4", "-F", target]
        elif scan_type == "full":
            command = ["nmap", "-sV", "-p-", target]
        else:
            command = ["nmap", target]

        result = subprocess.check_output(command, stderr=subprocess.STDOUT, text=True)
        return result

    except subprocess.CalledProcessError as e:
        return f"Error running Nmap: {e.output}"
