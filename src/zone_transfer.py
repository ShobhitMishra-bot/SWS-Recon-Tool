import dns.resolver
import dns.zone
import socket
from time import sleep
from prettytable import PrettyTable
from src.colors import YELLOW, GREEN, RED, BLUE, RESET

# Domain zone transfer function
def zone_transfer(domain, store, reportPath, vulnerability):

    print(f"\n{BLUE}[*] Starting domain zone transfer attack...\n")
    sleep(0.2)
    hosts = []
    ns = []
    nsVuln = []

    # iterating through name servers to attack everyone
    try:
        name_servers = dns.resolver.resolve(domain, 'NS')
        for n in name_servers:
            ip = dns.resolver.resolve(n.target, 'A')
            ns.append(str(n))
            for i in ip:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(str(i), domain))
                    for h in zone:
                        hosts.append(h)
                    if zone:
                        nsVuln.append(n)
                except Exception as e:
                    print(f"[{YELLOW}!{RESET}] NS {n} {RED}refused zone transfer!")
                    continue
    except:
        print(f"[{YELLOW}!{RESET}] Unable to try zone transfer")

    if nsVuln:
        for i in nsVuln:
            vulnerability.append(f"Infra, DNS Zone Transfer, Certain, [5.3](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N), Name Server: {i}")

    # open file to write
    if hosts:

        if store:
            f = open(reportPath, "a")
            f.write(f"\n\n## Zone transfer from {domain}\n\n")
            f.write(f"The domain {domain} has {len(ns)} Name Servers:\n")
            f.write("| Name Servers |\n|--------------|\n")
            for n in ns:
                f.write(f"| {n} |\n")
            f.write("\n\n")
            f.write("|" + " ZONE TRANSFER \t\t\t\t| IP \t\t\t|\n" + "|" + "-"*47 + "|" + "-"*23 + "|\n")

        table = PrettyTable(["ZONE TRANSFER", "IP"])
        for i in hosts:
            if '@' not in i:
                s = str(i) + "." + domain
                try:
                    ip = socket.gethostbyname(s)
                except:
                    ip = "Not found!"

                if store:
                    f.write(f"| {s} | {ip} |\n")
                table.add_row([s, ip])
                table.align["ZONE TRANSFER"] = "l"

        print(table)

        if store:
            f.close()
