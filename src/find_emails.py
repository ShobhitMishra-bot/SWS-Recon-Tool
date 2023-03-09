import requests
import re
import math
import sys
from bs4 import BeautifulSoup as bs
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

# request email pages
def request_find_email(domain, url_search, token, page):
    emails = []
    url = url_search + str(token) + str(page)
    r = requests.get(url, timeout=4).text
    soup = bs(r, 'html.parser')
    for link in soup.find_all('a'):
        if f"@{domain}" in link.get('href'):
            email = link.get('href')[8:]
            if email not in emails:
                emails.append(email)
    if emails:
        return emails
    else:
        return None

def find_emails(domain, store, reportPath, MAX_EMAILS, THREADS):
    print(f"\n{BLUE}[*] Searching for emails...\n")

    headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36"}
    page = 1
    last_page = None
    emails = []
    url_skymem = "http://www.skymem.info/srch"
    url_search = "http://www.skymem.info/domain/"

    try:
        r = requests.get(url_skymem, headers=headers, params={"q": domain}, timeout=4).text
        soup = bs(r, 'html.parser')
        token = ""
        for link in soup.find_all('a'):
            if "domain" in link.get('href'):
                token = link.get('href')[8:35]

        if token:
            url = url_search + str(token) + str(page)
            r = requests.get(url, timeout=4).text
            soup = bs(r, 'html.parser')
            for link in soup.find_all('small'):
                if "emails)" in link.text:
                    last_page = math.ceil(int(re.findall("[0-9]+",link.text)[0]) / 5)
                    break

        if last_page is not None and last_page < int(MAX_EMAILS / 5):
            pool = concurrent.futures.ThreadPoolExecutor(max_workers=THREADS)
            data = (pool.submit(request_find_email, domain, url_search, token, p) for p in range(page, last_page + 1))
            for resp in concurrent.futures.as_completed(data):
                resp = resp.result()
                if resp is not None:
                    for e in resp:
                        if e not in emails:
                            emails.append(e)

        if last_page is not None and last_page > int(MAX_EMAILS / 5):
            pool = concurrent.futures.ThreadPoolExecutor(max_workers=THREADS)
            data = (pool.submit(request_find_email, domain, url_search, token, p) for p in range(page, 11))
            for resp in concurrent.futures.as_completed(data):
                resp = resp.result()
                if resp is not None:
                    for e in resp:
                        if e not in emails:
                            emails.append(e)
                if len(emails) >= MAX_EMAILS:
                    break

        if emails:
            print(f"[{GREEN}+{RESET}] {len(emails)} Emails found:\n")
            for e in emails:
                print(f"\t{GREEN}-{RESET} {e}")
            if store:
                f = open(reportPath, "a")
                f.write(f"\n\n## Emails found\n\n")
                f.write(f"**{len(emails)} Emails found:**\n\n")
                for e in emails:
                    f.write(f"\n- **{e}**")
                f.close()
        else:
            print(f"[{YELLOW}!{RESET}] No emails found.")
    except KeyboardInterrupt:
        sys.exit(f"[{YELLOW}!{RESET}] Interrupt handler received, exiting...\n")
    except:
        print(f"[{YELLOW}!{RESET}] No emails found.")
        pass
