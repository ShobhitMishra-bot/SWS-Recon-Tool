import requests
import json
import sys
from time import sleep
from src.colors import YELLOW, GREEN, RED, BLUE, RESET
from urllib.parse import urlparse

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

# CORS testing function
# Based on Corsy - https://github.com/s0md3v/Corsy
def cors_testing(endpoint, headers, srcPath, domain):
    try:
        r = requests.get("https://raw.githubusercontent.com/h41stur/SWS/main/src/references_recon.json", verify=False,
                         timeout=10)
        CORS_VULN = json.loads(r.text)
        CORS_VULN = CORS_VULN["CORS"]
    except:
        with open(srcPath + "references_recon.json", "r") as file:
            CORS_VULN = json.load(file)
            CORS_VULN = CORS_VULN["CORS"]

    try:
        # origin reflected
        origin = 'https://h41stur.com'
        headers['Origin'] = origin
        header = ''
        r = requests.get(endpoint, headers=headers, verify=False, timeout=5)
        h = r.headers
        for key, value in h.items():
            if key.lower() == 'access-control-allow-origin':
                header = h
            if header:
                acao, acac = header.get('access-control-allow-origin', None), headers.get(
                    'access-control-allow-credentials', None)
                if acao and acao == (origin):
                    data = CORS_VULN['origin reflected']
                    data['acao header'] = acao
                    data['acac header'] = acac
                    return {endpoint: data}

        # post-domain wildcard
        origin = 'https://' + domain + '.h41stur.com'
        headers['Origin'] = origin
        header = ''
        r = requests.get(endpoint, headers=headers, verify=False, timeout=5)
        h = r.headers
        for key, value in h.items():
            if key.lower() == 'access-control-allow-origin':
                header = h
            if header:
                acao, acac = header.get('access-control-allow-origin', None), headers.get(
                    'access-control-allow-credentials', None)
                if acao and acao == (origin):
                    data = CORS_VULN['post-domain wildcard']
                    data['acao header'] = acao
                    data['acac header'] = acac
                    return {endpoint: data}

        # pre-domain wildcard
        origin = 'https://' + 'h41stur' + domain
        headers['Origin'] = origin
        header = ''
        r = requests.get(endpoint, headers=headers, verify=False, timeout=5)
        h = r.headers
        for key, value in h.items():
            if key.lower() == 'access-control-allow-origin':
                header = h
            if header:
                acao, acac = header.get('access-control-allow-origin', None), headers.get(
                    'access-control-allow-credentials', None)
                if acao and acao == (origin):
                    data = CORS_VULN['pre-domain wildcard']
                    data['acao header'] = acao
                    data['acac header'] = acac
                    return {endpoint: data}

        # null origin allowed
        origin = 'null'
        headers['Origin'] = origin
        header = ''
        r = requests.get(endpoint, headers=headers, verify=False, timeout=5)
        h = r.headers
        for key, value in h.items():
            if key.lower() == 'access-control-allow-origin':
                header = h
            if header:
                acao, acac = header.get('access-control-allow-origin', None), headers.get(
                    'access-control-allow-credentials', None)
                if acao and acao == (origin):
                    data = CORS_VULN['null origin allowed']
                    data['acao header'] = acao
                    data['acac header'] = acac
                    return {endpoint: data}

        # unrecognized underscore
        origin = 'https://' + domain + '_.h41stur.com'
        headers['Origin'] = origin
        header = ''
        r = requests.get(endpoint, headers=headers, verify=False, timeout=5)
        h = r.headers
        for key, value in h.items():
            if key.lower() == 'access-control-allow-origin':
                header = h
            if header:
                acao, acac = header.get('access-control-allow-origin', None), headers.get(
                    'access-control-allow-credentials', None)
                if acao and acao == (origin):
                    data = CORS_VULN['unrecognized underscore']
                    data['acao header'] = acao
                    data['acac header'] = acac
                    return {endpoint: data}

        # broken parser
        origin = 'https://' + domain + '%60.h41stur.com'
        headers['Origin'] = origin
        header = ''
        r = requests.get(endpoint, headers=headers, verify=False, timeout=5)
        h = r.headers
        for key, value in h.items():
            if key.lower() == 'access-control-allow-origin':
                header = h
            if header:
                acao, acac = header.get('access-control-allow-origin', None), headers.get(
                    'access-control-allow-credentials', None)
                if acao and '`.h41stur.com' in acao:
                    data = CORS_VULN['broken parser']
                    data['acao header'] = acao
                    data['acac header'] = acac
                    return {endpoint: data}

        # unescaped regex
        loc = urlparse(endpoint).netloc
        if loc.count(".") > 1:
            origin = 'https://' + loc.replace(".", "x", 1)
            headers['Origin'] = origin
            header = ''
            r = requests.get(endpoint, headers=headers, verify=False, timeout=5)
            h = r.headers
            for key, value in h.items():
                if key.lower() == 'access-control-allow-origin':
                    header = h
                if header:
                    acao, acac = header.get('access-control-allow-origin', None), headers.get(
                        'access-control-allow-credentials', None)
                    if acao and acao == (origin):
                        data = CORS_VULN['unescaped regex']
                        data['acao header'] = acao
                        data['acac header'] = acac
                        return {endpoint: data}

        # http origin allowed
        origin = 'http://' + domain
        headers['Origin'] = origin
        header = ''
        r = requests.get(endpoint, headers=headers, verify=False, timeout=5)
        h = r.headers
        for key, value in h.items():
            if key.lower() == 'access-control-allow-origin':
                header = h
            if header:
                acao, acac = header.get('access-control-allow-origin', None), headers.get(
                    'access-control-allow-credentials', None)
                if acao and acao.startswith('http://'):
                    data = CORS_VULN['http origin allowed']
                    data['acao header'] = acao
                    data['acac header'] = acac
                    return {endpoint: data}

        # wildcard value and third party allowed
        loc = urlparse(endpoint).netloc
        origin = 'https://' + domain
        headers['Origin'] = origin
        header = ''
        r = requests.get(endpoint, headers=headers, verify=False, timeout=5)
        h = r.headers
        for key, value in h.items():
            if key.lower() == 'access-control-allow-origin':
                header = h
            if header:
                acao, acac = header.get('access-control-allow-origin', None), headers.get(
                    'access-control-allow-credentials', None)
                if acao and acao == "*":
                    data = CORS_VULN['wildcard value']
                    data['acao header'] = acao
                    data['acac header'] = acac
                    return {endpoint: data}

                if loc:
                    if urlparse(acao).netloc and urlparse(acao).netloc != loc:
                        data = CORS_VULN['third party allowed']
                        data['acao header'] = acao
                        data['acac header'] = acac
                        return {endpoint: data}

    except requests.exceptions.RequestException as e:
        if 'Failed to establish a new connection' in str(e):
            print(f"[{YELLOW}!{RESET}] URL {endpoint} is unreachable")
        elif 'requests.exceptions.TooManyRedirects:' in str(e):
            print(f"[{YELLOW}!{RESET}] URL {endpoint} has too many redirects")


# CORS misconfiguration function
def cors(domain, store, reportPath, subs, srcPath, vulnerability, THREADS):
    print(f"\n{BLUE}[*] Searching for CORS misconfiguration...\n")
    sleep(0.2)
    if domain not in subs:
        subs.append(domain)

    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip',
        'DNT': '1',
        'Connection': 'close',
    }

    endpoints = []
    schemas = ['https://', 'http://']
    scan = []

    for s in subs:

        #### Take a long long time
        # Consulting wayback machine
        # try:
        #    r = requests.get(f"http://web.archive.org/cdx/search/cdx?url=*.{s}/*&output=json&fl=original&collapse=urlkey", timeout=10)
        #    resp = r.json()
        #    resp = resp[1:]
        #    for i in resp:
        #        if i[0] not in endpoints:
        #            endpoints.append(i[0])
        # except:
        #    pass

        # Consulting URLScan
        # try:
        #    r = requests.get(f"https://urlscan.io/api/v1/search/?q=domain:{s}", timeout=10)
        #    resp = json.loads(r.text)
        #    resp = resp["results"]
        #    for i in resp:
        #        i = i["task"]["url"]
        #        if i not in endpoints:
        #            endpoints.append(i)
        # except:
        #    pass

        for schema in schemas:
            u = schema + s
            if u not in endpoints and "*" not in u:
                endpoints.append(u)

    # iterating on endpoints
    if endpoints:

        pool = concurrent.futures.ThreadPoolExecutor(max_workers=THREADS)
        data = (pool.submit(cors_testing, endpoint, headers, srcPath, domain) for endpoint in endpoints)
        for resp in concurrent.futures.as_completed(data):
            resp = resp.result()
            if resp is not None:
                scan.append(resp)

        if scan:
            if store:
                f = open(reportPath, "a")
                f.write(f"\n\n## CORS misconfigurations\n\n")
                f.close()
            for resp in scan:
                for i in resp:
                    print(f"\n[{GREEN}+{RESET}] {i}")
                    print(f"\t{GREEN}-{RESET} Type: {resp[i]['class']}")
                    print(f"\t{GREEN}-{RESET} Description: {resp[i]['description']}")
                    print(f"\t{GREEN}-{RESET} Severity: {resp[i]['severity']}")
                    print(f"\t{GREEN}-{RESET} Exploit: {resp[i]['exploitation']}")
                    print(f"\t{GREEN}-{RESET} ACAO Header: {resp[i]['acao header']}")
                    print(f"\t{GREEN}-{RESET} ACAC header: {resp[i]['acac header']}")
                    vulnerability.append(f"WEB, CORS Misconfiguration, Certain, {resp[i]['severity']}, URL: {i}")
                    if store:
                        f = open(reportPath, "a")
                        f.write(f"\n\n### {i}\n\n")
                        f.write(f"\n\t- Type: {resp[i]['class']}")
                        f.write(f"\n\t- Description: {resp[i]['description']}")
                        f.write(f"\n\t- Severity: {resp[i]['severity']}")
                        f.write(f"\n\t- Exploit: {resp[i]['exploitation']}")
                        f.write(f"\n\t- ACAO Header: {resp[i]['acao header']}")
                        f.write(f"\n\t- ACAC Header: {resp[i]['acac header']}")
                        f.close()

        else:
            print(f"[{RED}-{RESET}] No CORS misconfiguration found.")
