import subprocess
import json
import os

# Per-tool subprocess timeouts in seconds
TOOL_TIMEOUTS = {
    'quick':          300,
    'full':           3600,
    'os_detection':   300,
    'aggressive':     600,
    'udp':            600,
    'ping_sweep':     60,
    'service_version':300,
    'stealth':        300,
    'vuln':           600,
    'nikto':          600,
    'sqlmap':         1800,
    'subfinder':      120,
    'whatweb':        60,
    'gobuster':       600,
    'nuclei':         900,
    'wpscan':         300,
    'testssl':        300,
}

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
            command = ["wpscan", "--url", target, "--no-update", "--format", "json", "--disable-tls-checks"]
        elif scan_type == "testssl":
            # testssl.sh outputs structured JSON — use --jsonfile to capture it
            command = [
                "bash", "/opt/testssl/testssl.sh",
                "--severity", "LOW",
                "--quiet",
                "--nodns", "min",
                "--jsonfile", "/tmp/testssl_output.json",
                "--warnings", "off",
                "--color", "0",
                target,
            ]
        else:
            # Nmap modes
            nmap_modes = {
                "quick":          ["nmap", "-T4", "-F", "--", target],
                "full":           ["nmap", "-sV", "-p-", "--", target],
                "os_detection":   ["nmap", "-O", "--", target],
                "aggressive":     ["nmap", "-A", "--", target],
                "udp":            ["nmap", "-sU", "--", target],
                "ping_sweep":     ["nmap", "-sn", "--", target],
                "service_version":["nmap", "-sV", "--", target],
                "stealth":        ["nmap", "-sS", "--", target],
                "vuln":           ["nmap", "--script", "vuln", "--", target],
            }
            command = nmap_modes.get(scan_type, ["nmap", "--", target])

        timeout = TOOL_TIMEOUTS.get(scan_type, 600)

        result = subprocess.check_output(
            command,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )

        json_result = None

        if scan_type == "nuclei":
            json_result = [json.loads(line) for line in result.splitlines() if line.strip()]

        elif scan_type == "wpscan":
            try:
                json_result = json.loads(result)
            except json.JSONDecodeError:
                pass

        elif scan_type == "testssl":
            # Read the JSON file testssl wrote
            try:
                json_path = "/tmp/testssl_output.json"
                if os.path.exists(json_path):
                    with open(json_path, "r") as f:
                        json_result = json.load(f)
                    os.remove(json_path)   # clean up
            except (json.JSONDecodeError, IOError):
                pass

        return result, json_result

    except subprocess.TimeoutExpired:
        raise RuntimeError(f"{scan_type} scan timed out after {TOOL_TIMEOUTS.get(scan_type, 600)}s")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Tool exited with code {e.returncode}:\n{e.output}")
    except Exception as e:
        raise RuntimeError(f"Unexpected error: {str(e)}")
