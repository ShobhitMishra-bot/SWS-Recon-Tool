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
    


# portscan request function
def portscan_request(sub, p):

    banner = None
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        status = s.connect_ex((sub, p))
        s.close()
    except socket.gaierror:
        return None

    if status == 0:
        print(f"{GREEN}-{RESET} Discovered open port: {GREEN}{sub} {YELLOW}{p}")

        context = ssl._create_unverified_context()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        try:
            s.connect((sub, p))
            s = context.wrap_socket(s, server_hostname=sub)
            s.send("SWS\r\n".encode())
            banner = s.recv(200).decode().split("\r\n\r\n")[0].strip()
            s.close()
        except (TimeoutError, ssl.SSLError, ConnectionResetError):
            s.close()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            try:
                s.connect((sub, p))
                s.send("SWS\r\n".encode())
                banner = s.recv(200).decode()
                banner = banner.split("\r\n\r\n")[0].strip()
            except (TimeoutError, ssl.SSLError, ConnectionResetError):
                banner = None
                s.close()
            s.close()

        return [p, banner]
    else:
        return None

# portscan function
def portscan(domain, store, reportPath, subs, THREADS):

    print(f"\n{BLUE}[*] Portscanning...\n")
    sleep(0.2)

    if domain not in subs:
        subs.append(domain)

    top_ports = [7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143, 144, 179,
                 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993,
                 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717,
                 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800,
                 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768,
                 49152, 49153, 49154, 49155, 49156, 49157]

    scan = []
    results = {}

    for sub in subs:
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=THREADS)
        data = (pool.submit(portscan_request, sub, p) for p in top_ports)
        for resp in concurrent.futures.as_completed(data):
            resp = resp.result()
            if resp is not None and resp not in scan:
                scan.append(resp)
        if scan:
            results.update({sub: scan})
            scan = []

    if results:
        print(f"\n\n{BLUE}[*] Trying to get some banners...")
        if store:
            f = open(reportPath, "a")
            f.write(f"\n\n## Portscan Results\n\n")
            f.close()
        for i in results:
            print(f"\n[{GREEN}+{RESET}] ports from {YELLOW}{i}\n")
            if store:
                f = open(reportPath, "a")
                f.write(f"\n\n### Ports from **{i}**\n\n")
                for p in results[i]:
                    f.write(f"- Discovered open port: **{i}:{p[0]}**\n")
                f.write("\n### Banners grabbed:\n")
                f.close()
            for p in results[i]:
                if p[1] is not None:
                    print(f"{GREEN}-{RESET} Port {YELLOW}{p[0]}{RESET}:", end="\n\n")
                    print(f"{GREEN}{p[1]}", end="\n\n")
                    if store:
                        f = open(reportPath, "a")
                        f.write(f"\n- Port {p[0]}.\n\n")
                        f.write(f"```\n{p[1]}\n```")
                        f.close()
    else:
        print(f"[{YELLOW}!{RESET}] Unable to enumerate any open port!")

