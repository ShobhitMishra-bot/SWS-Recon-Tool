import requests
import json
import re
import sys
import socket
from time import sleep
from prettytable import PrettyTable
from src.colors import YELLOW, GREEN, RED, BLUE, RESET

import urllib3
import warnings
urllib3.disable_warnings()
warnings.simplefilter("ignore")

# Subdomain discovery function
def subDomain(domain, store, reportPath):

    print(f"\n{BLUE}[*] Discovering subdomains from {domain}...\n")
    sleep(0.1)
    subDoms = []

    # Consulting crt.sh
    try:
        r = requests.get(f"https://crt.sh/?q={domain}&output=json", timeout=20)
        file = json.dumps(json.loads(r.text), indent=4)
        sub_domains = sorted(set(re.findall(r'"common_name": "(.*?)"', file)))
        for sub in sub_domains:
            if sub.endswith(domain) and sub not in subDoms:
                subDoms.append(sub)
    except KeyboardInterrupt:
        sys.exit(f"[{YELLOW}!{RESET}] Interrupt handler received, exiting...\n")
    except:
        pass

    # Consulting Hackertarget
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=20)
        sub_domains = re.findall(f'(.*?),', r.text)
        for sub in sub_domains:
            if sub.endswith(domain) and sub not in subDoms:
                subDoms.append(sub)
    except KeyboardInterrupt:
        sys.exit(f"[{YELLOW}!{RESET}] Interrupt handler received, exiting...\n")
    except:
        pass

    # Consulting RapidDNS
    try:
        r = requests.get(f"https://rapiddns.io/subdomain/{domain}", timeout=20)
        sub_domains = re.findall(r'target="_blank".*?">(.*?)</a>', r.text)
        for sub in sub_domains:
            if sub.endswith(domain) and sub not in subDoms:
                subDoms.append(sub)
    except KeyboardInterrupt:
        sys.exit(f"[{YELLOW}!{RESET}] Interrupt handler received, exiting...\n")
    except:
        pass

    # Consulting AlienVault
    try:
        r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", timeout=20)
        sub_domains = sorted(set(re.findall(r'"hostname": "(.*?)"', r.text)))
        for sub in sub_domains:
            if sub.endswith(domain) and sub not in subDoms:
                subDoms.append(sub)
    except KeyboardInterrupt:
        sys.exit(f"[{YELLOW}!{RESET}] Interrupt handler received, exiting...\n")
    except:
        pass

    # Consulting URLScan
    try:
        r = requests.get(f"https://urlscan.io/api/v1/search/?q={domain}", timeout=20)
        sub_domains = sorted(set(re.findall(r'https://(.*?).' + domain, r.text)))
        for sub in sub_domains:
            if sub.endswith(domain) and sub not in subDoms:
                subDoms.append(sub)
    except KeyboardInterrupt:
        sys.exit(f"[{YELLOW}!{RESET}] Interrupt handler received, exiting...\n")
    except:
        pass

    # Consulting Riddler
    try:
        r = requests.get(f"https://riddler.io/search/exportcsv?q=pld:{domain}", timeout=20)
        sub_domains = re.findall(r'\[.*?\]",.*?,(.*?),\[', r.text)
        for sub in sub_domains:
            if sub.endswith(domain) and sub not in subDoms:
                subDoms.append(sub)
    except KeyboardInterrupt:
        sys.exit(f"[{YELLOW}!{RESET}] Interrupt handler received, exiting...\n")
    except:
        pass

    # Consulting ThreatMiner
    try:
        r = requests.get(f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5", timeout=20)
        file = json.loads(r.ontent)
        sub_domains = file['results']
        for sub in sub_domains:
            if sub.endswith(domain) and sub not in subDoms:
                subDoms.append(sub)
    except KeyboardInterrupt:
        sys.exit(f"[{YELLOW}!{RESET}] Interrupt handler received, exiting...\n")
    except:
        pass


    # open file to write
    if subDoms:
        if store:
            f = open(reportPath, "a")
            f.write(f"\n\n## Subdomains from {domain}\n\n")
            f.write("|" + " SUBDOMAINS    \t\t\t\t| IP \t\t\t|\n" + "|" + "-"*47 + "|" + "-"*23 + "|\n")

        # interact through list and check the lenght
        table = PrettyTable([f"SUBDOMAINS", f"IP"])
        for s in subDoms:
            try:
                ip = socket.gethostbyname(s)
            except:
                ip = "Not found!"
            if store:
                f.write(f"| {s} | {ip} |\n")
            table.add_row([s, ip])
            table.align["SUBDOMAINS"] = "l"

        print(table)
        print(f"\n{BLUE}Total discovered sudomains: {GREEN}" + str(len(subDoms)))

        if store:
            f.write("\n\n**Total discovered sudomains: " + str(len(subDoms)) + "**")
            f.close()

        return subDoms