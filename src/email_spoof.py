import dns.resolver
import socket
import re
from time import sleep
from src.colors import YELLOW, GREEN, RED, BLUE, RESET

# E-mail spoof function
def spoof(domain, vulnerability):
    print(f"\n{BLUE}[*] Checking SPF and DMARC records...\n")
    sleep(0.2)

    spoofable = False

    dns_resolver = dns.resolver.Resolver()
    # get DNS server
    dns_server = ""
    dns_resolver.nameservers = ['1.1.1.1']
    query = dns_resolver.resolve(domain, "SOA")
    if query:
        for d in query:
            d = socket.gethostbyname(str(d.mname))
            dns_resolver.nameservers[0] = d
    else:
        dns_resolver.nameservers[0] = '1.1.1.1'

    # get SPF record
    spf = None
    try:
        spf = dns_resolver.resolve(domain, 'TXT')
    except dns.resolver.NoAnswer:
        print(f"[{YELLOW}!{RESET}] No TXT record found!")
        return
    except:
        dns_resolver.nameservers[0] = '1.1.1.1'
        spf = dns_resolver.resolve(domain, 'TXT')
    spf_rec = None
    for d in spf:
        if 'spf1' in str(d):
            spf_rec = str(d).replace('"', "")
            break
    # get all property
    if spf_rec:
        n = spf_rec.count(" ~all") + spf_rec.count(" ?all") + spf_rec.count(" -all")
        if n == 1:
            spf_all = re.search("[-,~,?]all", spf_rec).group(0)
        elif n == 0:
            spf_all = None
        else:
            spf_all = "many"

        # get spf includes
        includes = []
        n = len(re.compile("[ ,+]a[ , :]").findall(spf_rec))
        n += len(re.compile("[ ,+]mx[ ,:]").findall(spf_rec))
        n += len(re.compile("[ ]ptr[ ]").findall(spf_rec))
        n += len(re.compile("exists[:]").findall(spf_rec))
        for i in range(0, n):
            includes.append("SWS")
        for i in spf_rec.split(" "):
            item = i.replace("include:", "")
            if "include:" in i:
                includes.append(item)
        spf_includes = len(includes)
    else:
        print(f"[{YELLOW}!{RESET}] No SPF record found!")

    # get DMARC record
    dmarc_rec = ""
    try:
        try:
            dmarc = dns_resolver.resolve(f"_dmarc.{domain}", 'TXT')
        except Exception as e:
            dns_resolver.nameservers[0] = '1.1.1.1'
            dmarc = dns_resolver.resolve(f"_dmarc.{domain}", 'TXT')
        dmarc_rec = ""
        for d in dmarc:
            if "DMARC" in str(d):
                dmarc_rec = str(d).replace('"', "")
                break
    except:
        print(f"[{YELLOW}!{RESET}] No DMARC record found!.")
    # get DMARC properties
    p = None
    aspf = None
    sp = None
    pct = None
    if dmarc_rec:
        # get policy
        if "p=" in dmarc_rec:
            p = dmarc_rec.split("p=")[1].split(";")[0]
        # get aspf
        if "aspf=" in dmarc_rec:
            aspf = dmarc_rec.split("aspf=")[1].split(";")[0]
        # get sp
        if "sp=" in dmarc_rec:
            sp = dmarc_rec.split("sp=")[1].split(";")[0]
        # get pct
        if "pct=" in dmarc_rec:
            pct = dmarc_rec.split("pct=")[1].split(";")[0]

    # check spoof
    try:
        if pct and int(pct) != 100:
            spoofable = True
            print(f"[{GREEN}+{RESET}] Possible spoofing for {domain}\n")
            print(
                f"\t{GREEN}- Reason{RESET}: The pct tag (percentage) is lower than 100%, DMARC record has instructed the receiving server to reject {pct}% of email that fails DMARC authentication and to send a report about it to the mailto: address in the record.")
        elif spf_rec is None:
            if p is None:
                spoofable = True
                print(f"[{GREEN}+{RESET}] Possible spoofing for {domain}\n")
                print(f"\t{GREEN}- Reason{RESET}: Domain has no SPF record or DMARC tag \"p\" (policy).")
        elif spf_includes > 10 and p is None:
            spoofable = True
            print(f"[{GREEN}+{RESET}] Possible spoofing for {domain}\n")
            print(f"\t{GREEN}- Reason{RESET}: Too many include records without DMARC policy can override each other")
        elif spf_all == "many":
            if p is None:
                spoofable = True
                print(f"[{GREEN}+{RESET}] Possible spoofing for{domain}\n")
                print(f"\t{GREEN}- Reason{RESET}: More than one record \"all\" with no DMARC \"p\" tag (policy).")
        elif spf_all and p is None:
            spoofable = True
            print(f"[{GREEN}+{RESET}] Possible spoofing for {domain}\n")
            print(f"\t{GREEN}- Reason{RESET}: DMARC without \"p\" tag (policy)")
        elif spf_all == "-all":
            if p and aspf and sp == "none":
                spoofable = True
                print(f"[{GREEN}+{RESET}] Possible subdomain spoofing for {domain}\n")
                print(
                    f"\t{GREEN}- Reason{RESET}: SPF with hardfail (-all), but DMARC without \"sp\" tag (subdomain policy)")
            elif aspf is None and sp == "none":
                spoofable = True
                print(f"[{GREEN}+{RESET}] Possible subdomain spoofing for {domain}\n")
                print(
                    f"\t{GREEN}- Reason{RESET}: SPF with hardfail (-all), but DMARC \"sp\" tag (subdomain policy) is \"none\" and \"aspf\" tag (SPF aligment) missing.")
            elif p == "none" and (aspf == "r" or aspf is None) and sp is None:
                spoofable = True
                print(f"[{GREEN}+{RESET}] Possible Mailbox dependant spoofing for {domain}\n")
                print(
                    f"\t{GREEN}- Reason{RESET}: SPF with hardfail (-all), but DMARC \"aspf\" tag (SPF aligment) is \"r\" (relaxed) or missing, \"p\" tag (policy) and \"sp\" tag (subdomain policy) missing.")
            elif p == "none" and aspf == "r" and (sp == "reject" or sp == "quarentine"):
                spoofable = True
                print(f"[{GREEN}+{RESET}] Possible Organizational spoofing for {domain}\n")
                print(
                    f"\t{GREEN}- Reason{RESET}: SPF with hardfail (-all), but DMARC \"aspf\" tag (SPF aligment) is \"r\" (relaxed), \"p\" tag (policy) is \"none\" and \"sp\" tag (subdomain policy) is \"reject\" or \"quarentine\". This allows for spoofing within the organization.")
            elif p == "none" and aspf is None and (sp == "reject" or sp == "quarentine"):
                spoofable = True
                print(f"[{GREEN}+{RESET}] Possible Organizational spoofing for {domain}\n")
                print(
                    f"\t{GREEN}- Reason{RESET}: SPF with hardfail (-all), but DMARC \"aspf\" tag (SPF aligment) is missing and \"sp\" tag (subdomain policy) is \"reject\" or \"quarentine\". This allows for spoofing within the organization.")
            elif p == "none" and aspf is None and sp == "none":
                spoofable = True
                print(f"[{GREEN}+{RESET}] Possible subdomain spoofing for {domain}\n")
                print(
                    f"\t{GREEN}- Reason{RESET}: SPF with hardfail (-all), but DMARC \"p\" tag (policy) and \"sp\" tag (subdomain policy) is \"none\", and \"aspf\" tag (SPF aligment) is missing.")
            else:
                print(f"[{YELLOW}!{RESET}] Spoofing not possible for {domain}")
        elif spf_all == "~all":
            if p == "none" and sp == "reject" or sp == "quarentine":
                spoofable = True
                print(f"[{GREEN}+{RESET}] Possible Organizational subdomain spoofing for {domain}\n")
                print(
                    f"\t{GREEN}- Reason{RESET}: SPF with softfail (~all), but DMARC \"p\" tag (policy) is \"none\" and \"sp\" tag (subdomain policy) is \"reject\" or \"quarentine\". This allows for spoofing within the organization.")
            elif p == "none" and sp is None:
                spoofable = True
                print(f"[{GREEN}+{RESET}] Possible spoofing for {domain}\n")
                print(
                    f"\t{GREEN}- Reason{RESET}: SPF with softfail (~all), but DMARC \"p\" tag (policy) is \"none\" and \"sp\" tag (subdomain policy) is missing.")
            elif p == "none" and sp == "none":
                spoofable = True
                print(f"[{GREEN}+{RESET}] Possible Organizational subdomain spoofing for {domain}\n")
                print(
                    f"\t{GREEN}- Reason{RESET}: SPF with softfail (~all), but DMARC \"p\" tag (policy) and \"sp\" tag (subdomain policy) is \"none\". This allows for spoofing within the organization.")
            elif (p == "reject" or p == "quarentine") and aspf is None and sp == "none":
                spoofable = True
                print(f"[{GREEN}+{RESET}] Possible subdomain spoofing for {domain}\n")
                print(
                    f"\t{GREEN}- Reason{RESET}: SPF with softfail (~all), but DMARC p tag (policy) is reject or quarentine, aspf tag (SPF aligment) is missing and sp tag (subdomain policy) is none.")
            elif (p == "reject" or p == "quarentine") and aspf and sp == "none":
                spoofable = True
                print(f"[{GREEN}+{RESET}] Possible subdomain spoofing for {domain}\n")
                print(
                    f"\t{GREEN}- Reason{RESET}: SPF with softfail (~all), but DMARC \"p\" tag (policy) is \"reject\" or \"quarentine\", \"aspf\" tag (SPF aligment) exists, but \"sp\" tag (subdomain policy) is \"none\".")
            else:
                print(f"[{YELLOW}!{RESET}] Spoofing not possible for {domain}")
        elif spf_all == "?all":
            if (p == "reject" or p == "quarentine") and aspf and sp == "none":
                spoofable = True
                print(f"[{GREEN}+{RESET}] Possible subdomain Mailbox dependant spoofing for {domain}\n")
                print(
                    f"\t{GREEN}- Reason{RESET}: SPF neutral (?all), but DMARC \"p\" tag (policy) is \"reject\" or \"quarentine\", \"aspf\" tag (SPF aligment) exists, but \"sp\" tag (subdomain policy) is \"none\".")
            elif (p == "reject" or p == "quarentine") and aspf is None and sp == "none":
                spoofable = True
                print(f"[{GREEN}+{RESET}] Possible subdomain Mailbox dependant spoofing for {domain}\n")
                print(
                    f"\t{GREEN}- Reason{RESET}: SPF neutral (?all), but DMARC \"p\" tag (policy) is \"reject\" or \"quarentine\", \"aspf\" tag (SPF aligment) is missing, but \"sp\" tag (subdomain policy) is \"none\".")
            elif p == "none" and aspf == "r" and sp is None:
                spoofable = True
                print(f"[{GREEN}+{RESET}] Possible spoofing for {domain}\n")
                print(
                    f"\t{GREEN}- Reason{RESET}: SPF neutral (?all), but DMARC \"p\" tag (policy) is \"none\", \"aspf\" tag (SPF aligment) is \"r\" (relaxed) and \"sp\" tag (subdomain policy) is missing.")
            elif p == "none" and aspf == "r" and sp == "none":
                spoofable = True
                print(f"[{GREEN}+{RESET}] Possible subdomain or organizational spoofing for {domain}\n")
                print(
                    f"\t{GREEN}- Reason{RESET}: SPF neutral (?all), but DMARC \"p\" tag (policy) is \"none\", \"aspf\" tag (SPF aligment) is \"r\" (relaxed) and \"sp\" tag (subdomain policy) is \"none\".")
            elif p == "none" and aspf == "s" or None and sp == "none":
                spoofable = True
                print(f"[{GREEN}+{RESET}] Possible subdomain spoofing for {domain}\n")
                print(
                    f"\t{GREEN}- Reason{RESET}: SPF neutral (?all), but DMARC \"p\" tag (policy) is \"none\", \"aspf\" tag (SPF aligment) is \"s\" (strict) and \"sp\" tag (subdomain policy) is \"none\".")
            elif p == "none" and aspf == "s" or None and sp is None:
                spoofable = True
                print(f"[{GREEN}+{RESET}] Possible subdomain Mailbox dependant spoofing for {domain}\n")
                print(
                    f"\t{GREEN}- Reason{RESET}: SPF neutral (?all), but DMARC \"p\" tag (policy) is \"none\", \"aspf\" tag (SPF aligment) is \"s\" (strict) or missing, and \"sp\" tag (subdomain policy) is missing")
            elif p == "none" and aspf and (sp == "reject" or sp == "quarentine"):
                spoofable = True
                print(f"[{GREEN}+{RESET}] Possible Organizational subdomain spoofing for {domain}\n")
                print(
                    f"\t{GREEN}- Reason{RESET}: SPF neutral (?all), but DMARC \"p\" tag (policy) \"none\", \"aspf\" tag (SPF aligment) exists, but \"sp\" tag (subdomain policy) is \"reject\" or \"quarentine\". This allows for spoofing within the organization.")
            elif p == "none" and aspf is None and sp == "reject":
                spoofable = True
                print(f"[{GREEN}+{RESET}] Possible Organizational subdomain spoofing for {domain}\n")
                print(
                    f"\t{GREEN}- Reason{RESET}: SPF neutral (?all), but DMARC \"p\" tag (policy) \"none\", \"aspf\" tag (SPF aligment) is missing, and \"sp\" tag (subdomain policy) is \"reject\". This allows for spoofing within the organization.")
            else:
                print(f"[{YELLOW}!{RESET}] Spoofing not possible for {domain}")
        else:
            print(f"[{YELLOW}!{RESET}] Spoofing not possible for {domain}")

    except Exception as e:
        print(f"[{YELLOW}!{RESET}] Unable to check!.")

    if spoofable:
        if spf_rec:
            print(f"\t{GREEN}- SPF{RESET}: {spf_rec}")
        if dmarc_rec:
            print(f"\t{GREEN}- DMARC{RESET}: {dmarc_rec}")
        vuln = f"Infra, E-mail Spoofing, Possible, [9.1](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N), TXT Record: \"{spf_rec}\""
        if not vuln in vulnerability:
            vulnerability.append(vuln)
