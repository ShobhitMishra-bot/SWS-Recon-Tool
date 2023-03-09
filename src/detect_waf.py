import requests
import json
import re
import sys
from time import sleep
from src.colors import YELLOW, GREEN, RED, BLUE, RESET

# threading
try:
    import concurrent.futures
except ImportError:
    print(f"[{YELLOW}!{RESET}] SWS needs python 3.4 > ro run!")
    sys.exit()

# request to detect WAF function
def request_waf(subdomain, srcPath):

    WAF = []
    try:
        r = requests.get("https://raw.githubusercontent.com/h41stur/SWS/main/src/references_recon.json", verify=False, timeout=10)
        wafSignatures = json.loads(r.text)
        wafSignatures = wafSignatures["WAF"]
    except:
        with open(srcPath + "references_recon.json", "r") as file:
            wafSignatures = json.load(file)
            wafSignatures = wafSignatures["WAF"]

    URL = f"https://{subdomain}/../../../../etc/passwd"
    try:
        r = requests.get(URL, verify=False, timeout=10)
        status = str(r.status_code)
        content = r.text
        headers = str(r.headers)
        cookie = str(r.cookies.get_dict())

        if int(status) >= 400:
            wafMatch = [0, None]
            for name, sign in wafSignatures.items():
                score = 0
                contentSign = sign["page"]
                statusSign = sign["code"]
                headersSign = sign["headers"]
                cookieSign = sign["cookie"]
                if contentSign:
                    if re.search(contentSign, content, re.I):
                        score += 1
                if statusSign:
                    if re.search(statusSign, status, re.I):
                        score += 0.5
                if headersSign:
                    if re.search(headersSign, headers, re.I):
                        score += 1
                if cookieSign:
                    if re.search(cookieSign, cookie, re.I):
                        score += 1
                if score > wafMatch[0]:
                    del wafMatch[:]
                    wafMatch.extend([score, name])

            if wafMatch[0] != 0:
                print(f"[{GREEN}+{RESET}] WAF {wafMatch[1]} detected on https://{subdomain}")
                return f"{subdomain},{wafMatch[1]}"
            else:
                print(f"[{RED}-{RESET}] WAF not detected on https://{subdomain}")
                return None
    except KeyboardInterrupt:
        sys.exit(f"[{YELLOW}!{RESET}] Interrupt handler received, exiting...\n")
    except:
        print(f"[{YELLOW}!{RESET}] URL https://{subdomain} not accessible")
        return None



# detect WAF function
def detect_waf(domain, store, reportPath, subs, srcPath, THREADS):

    print(f"\n{BLUE}[*] Detecting WAF...\n")
    sleep(0.2)
    if domain not in subs:
        subs.append(domain)
    WAF = []

    try:
        r = requests.get("https://raw.githubusercontent.com/h41stur/SWS/main/src/references_recon.json", verify=False, timeout=10)
        wafSignatures = json.loads(r.text)
        wafSignatures = wafSignatures["WAF"]

    except Exception as e:
        with open(srcPath + "references_recon.json", "r") as file:
            wafSignatures = json.load(file)
            wafSignatures = wafSignatures["WAF"]

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=THREADS)
    data = (pool.submit(request_waf, s, srcPath) for s in subs)
    for resp in concurrent.futures.as_completed(data):
        resp = resp.result()
        if resp is not None and resp not in WAF:
            WAF.append(resp)

    if WAF:
        if store:
            f = open(reportPath, "a")
            f.write(f"\n\n## WAFs detected on scope {domain}\n\n")
            f.write("|" + " URL \t\t\t\t| WAF \t\t\t|\n" + "|" + "-" *47 + "|" + "-" *23 + "|\n")

            for i in WAF:
                f.write(f"| {i.split(',')[0]} | {i.split(',')[1]} |\n")

        if store:
            f.close()
