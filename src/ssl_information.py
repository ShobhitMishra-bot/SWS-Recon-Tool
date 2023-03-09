import os
import ssl
import socket
import sys
from time import sleep
from src.colors import YELLOW, GREEN, RED, BLUE, RESET

# threading
try:
    import concurrent.futures
except ImportError:
    print(f"[{YELLOW}!{RESET}] SWS needs python 3.4 > ro run!")
    sys.exit()

result = []
partial = []
values = {}

def parse(value, key):
    dec = 0
    for i in value:
        if isinstance(i, tuple):
            for s in i:
                if isinstance(s, tuple):
                    for e in s:
                        if isinstance(e, tuple):
                            parse(e)
                        else:
                            dec = 1
                    if dec:
                        values.update(dict([s]))
                else:
                    pass
        else:
            d = {key: value}
            if d not in partial:
                partial.append(d)

def extract_ssl(s, srcPath):
    partial = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((s, 443))
        sock.close()

        context = ssl.create_default_context()
        sock = socket.socket()
        sock.settimeout(5)
        sock = context.wrap_socket(sock, server_hostname=s)

        try:
            sock.connect((s, 443))
            cert_info = sock.getpeercert()
        except:
            info = ssl.get_server_certificate((s, 443))
            file = open(f"{srcPath}/{s}.pem", "w")
            file.write(info)
            file.close()
            cert_info = ssl._ssl._test_decode_cert(f"{srcPath}/{s}.pem")
            os.remove(f"{srcPath}/{s}.pem")

        for key, value in cert_info.items():
            if isinstance(value, tuple):
                parse(value, key)
                for key, value in values.items():
                    d = {key: value}
                    if d not in partial:
                        partial.append(d)
                values.clear()
            else:
                d = {key: value}
                if d not in partial:
                    partial.append(d)
        sock.close()

        if partial is not None:
            resp = {"URL": s, "info": partial}
            return resp

    except:
        sock.close()
        print(f"[{RED}-{RESET}] An error has ocurred or unable to enumerate {RED}{s}")
        pass


def ssl_information(domain, store, srcPath, reportPath, subs, THREADS):
    print(f"\n{BLUE}[*] Extracting information from SSL Certificate...\n")

    sleep(0.2)
    if domain not in subs:
        subs.append(domain)

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=THREADS)
    data = (pool.submit(extract_ssl, s, srcPath) for s in subs)
    for resp in concurrent.futures.as_completed(data):
        resp = resp.result()
        if resp is not None:
            result.append(resp)

    if result:
        for pair in result:
            print(f"\n[{GREEN}+{RESET}] Results from {YELLOW}{pair['URL']}\n")
            for i in pair["info"]:
                for key, value in i.items():
                    if isinstance(value, tuple):
                        value = value[0]
                    print(f"{GREEN}-{RESET} {key}: {GREEN}{value}")
        if store:
            f = open(reportPath, "a")
            f.write(f"\n\n## SSL Certificate Information\n")
            for pair in result:
                f.write(f"\n### Results from {pair['URL']}\n")
                f.write("|" + " KEY \t\t\t\t| VALUE \t\t\t|\n" + "|" + "-" * 47 + "|" + "-" * 23 + "|\n")
                for i in pair["info"]:
                    for key, value in i.items():
                        if isinstance(value, tuple):
                            value = value[0]
                        f.write(f"| {key} | {value} |\n")
            f.close()

    else:
        print(f"[{YELLOW}!{RESET}] No SSL information found from {domain}")
