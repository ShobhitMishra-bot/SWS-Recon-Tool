import dns.zone
import dns.resolver
import wget
from prettytable import PrettyTable
from time import sleep
from src.colors import YELLOW, GREEN, RED, BLUE, RESET


# DNS information function
def dns_information(domain, store, dirFile, reportPath, vulnerability):

    print(f"\n{BLUE}[*] Discovering some DNS information from {domain}...\n")
    sleep(0.2)
    registry = []

    mail = ""
    txt = ""
    ns = ""
    try:
        mail = dns.resolver.resolve(domain, 'MX')
    except:
        pass
    if mail:
        print(f"[{GREEN}+{RESET}] Mail Servers:")
        for s in mail:
            registry.append(f"Mail Server,{str(s).split(' ')[1]}")
            print(f"\t {GREEN}-{RESET} {str(s).split(' ')[1]}")

    try:
        txt = dns.resolver.resolve(domain, 'TXT')
    except:
        pass
    if txt:

        reg = []

        print(f"\n[{GREEN}+{RESET}] TXT Records:")
        for i in txt:
            i = i.to_text()
            registry.append(f"TXT Records,{i}")
            if "?all" in i or "~all" in i or "spf" in i and "all" not in i:
                reg = i

            print(f"\t {GREEN}-{RESET} {i}")

        if reg:
            print(f"\n[{YELLOW}!{RESET}] {YELLOW}Possible e-mail spoofing vulnerability in TXT record:{RESET} {reg}")
            vulnerability.append \
                (f"Infra, E-mail Spoofing, Possible, [9.1](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N), TXT Record: {reg}")

    try:
        ns = dns.resolver.resolve(domain, 'NS')
    except:
        pass
    if ns:
        print(f"\n[{GREEN}+{RESET}] Name Servers:")
        for n in ns:
            registry.append(f"Name Server,{str(n)}")
            print(f"\t {GREEN}-{RESET} {str(n)}")

    if mail or txt or ns:
        if store:
            f = open(reportPath, "a")
            f.write(f"\n\n## DNS information from {domain}\n\n")
            f.write("|" + " KEY \t\t\t\t| VALUE \t\t\t|\n" + "|" + "-" *47 + "|" + "-" *23 + "|\n")

            for i in registry:
                i = i.split(",")
                f.write(f"|{i[0]}|{i[1]}|\n")

            file = ""
            try:
                filename = dirFile + "/" + "dnsmap.png"
                url = 'https://dnsdumpster.com/static/map/{}.png'.format(domain)
                def bar_progress(current, total, width=80):
                    pass
                file = wget.download(url, out=filename, bar=bar_progress)
            except Exception as e:
                pass

            if file:
                f.write(f"\n\n### DNS map from {domain}\n\n")
                f.write(f"![DNS map](./dnsmap.png)")

            f.close()

# Whois lookup function
def whois_lookup(domain, store, reportPath, vulnerability):

    print(f"\n{BLUE}[*] Performing WHOIS Lookup...\n")
    import whois
    sleep(2)
    lookup = []

    try:
        w = whois.whois(domain)
    except:
        w = whois.query(domain)

    try:
        for i in w:
            if i not in lookup:
                lookup.append(f"{i}~{w[i]}")
    except:
        print(f"\n[{YELLOW}!{RESET}]An error has ocurred or unable to whois {domain}")

    if lookup:

        if store:
            f = open(reportPath, "a")
            f.write(f"\n\n## Whois lookup from {domain}\n\n")
            f.write("|" + " KEY \t\t\t\t| VALUE \t\t\t|\n" + "|" + "-"*47 + "|" + "-"*23 + "|\n")

        table = PrettyTable(["KEY", "VALUE"])
        for i in lookup:
            s = i.split("~")[0]
            v = i.split("~")[1]

            if store:
                f.write(f"| {s} | {v} |\n")
            table.add_row([s, v])
            table.align = "l"

        print(table)

        if store:
            f.close()