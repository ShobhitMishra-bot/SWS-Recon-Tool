import sys
import requests
from prettytable import PrettyTable
from time import sleep
from src.colors import YELLOW, GREEN, RED, BLUE, RESET

import urllib3
import warnings
urllib3.disable_warnings()
warnings.simplefilter("ignore")

# threading
try:
    import concurrent.futures
except ImportError:
    print(f"[{YELLOW}!{RESET}] SWS needs python 3.4 > ro run!")
    sys.exit()

# backups request function
def request_bkp(subdomain, domain):
    ext = ["sql.tar", "tar", "tar.gz", "gz", "tar.bzip2", "sql.bz2", "sql.7z", "zip", "sql.gz", "7z"]
    hostname = domain.split(".")[0]
    filenames = [hostname, domain, "backup", "admin", "wordpress"]
    proto = ["http://", "https://"]

    for p in proto:
        for f in filenames:
            for e in ext:
                URL = f"{p}{subdomain}/{f}.{e}"
                try:
                    r = requests.get(URL, verify=False, timeout=4)
                    status = r.status_code
                except KeyboardInterrupt:
                    sys.exit(f"[{YELLOW}!{RESET}] Interrupt handler received, exiting...\n")
                except:
                    continue
                if status != 400:
                    return f"{URL},{status}"
                else:
                    return None


# search backups function
def search_backups(domain, store, reportPath, subs, THREADS):
    print(f"\n{BLUE}[*] Searching for backup files...\n")
    sleep(0.2)
    if domain not in subs:
        subs.append(domain)

    bkp = []

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=THREADS)
    data = (pool.submit(request_bkp, s, domain) for s in subs)
    for resp in concurrent.futures.as_completed(data):
        resp = resp.result()
        if resp is not None and resp not in bkp:
            bkp.append(resp)

    if bkp:

        if store:
            f = open(reportPath, "a")
            f.write(f"\n\n## Backup files found\n\n")
            f.write("|" + " URL \t\t\t\t| STATUS \t\t\t|\n" + "|" + "-" * 47 + "|" + "-" * 23 + "|\n")

        table = PrettyTable(["URL", "STATUS"])
        for b in bkp:
            s = b.split(",")[0]
            v = b.split(",")[1]
            if store:
                f.write(f"| {s} | {v} |\n")
            table.add_row([s, v])
            table.align["URL"] = "l"

        print(table)

        if store:
            f.close()

    else:
        print(f"[{RED}-{RESET}] No backup files found")
