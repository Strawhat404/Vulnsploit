import subprocess

def run_nmap(target):

    try:
        # -sV → service detection
        # -T4 → faster scan
        # -oN - → output normal format to stdout
        result = subprocess.check_output(
            ['nmap', '-sV', '-T4', '-oN', '-', target],
            stderr=subprocess.STDOUT,
            text=True
        )
        return result
    except subprocess.CalledProcessError as e:
        return f"An error occurred while running nmap: {e.output}"
