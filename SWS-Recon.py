#!/usr/bin/env python3

import argparse
import sys
import socket
import pathlib
import os
import tldextract
from colorama import init as colorama_init

# SWS libs
from src.email_spoof import spoof
from src.portscan import portscan
from src.dorks import dorks
from src.cors import cors
from src.vuln_vectors import hunt
from src.enum_tech import tech
from src.search_backups import search_backups
from src.detect_waf import detect_waf
from src.find_repos import find_repos
from src.subdomain_takeover import subtake
from src.zone_transfer import zone_transfer
from src.subdomains import subDomain
from src.dns_information import dns_information, whois_lookup
from src.find_emails import find_emails
from src.ssl_information import ssl_information
from src.js_links import js_links
from src.colors import YELLOW, GREEN, RED, BLUE, RESET

# Color config
if os.name == 'nt':
    colorama_init(autoreset=True, convert=True)
    os.system('cls')
else:
    colorama_init(autoreset=True)

# threading
try:
    import concurrent.futures
except ImportError:
    print(f"[{YELLOW}!{RESET}] SWS-Recon needs python 3.4 > ro run!")
    sys.exit()

# Args parsing
def arguments():
    
    a = argparse.ArgumentParser(description="SWS Recon Tool")
    a.add_argument("-d", "--domain", help="Domain to start recon", required=False)
    a.add_argument("-o", "--output", help="Save a directory containing Markdown file with recon report.", required=False, action='store_true')
    a.add_argument("-A", "--all", help="Permorm all options at once, except -s and -o (which can be added manually)", required=False, action='store_true')
    a.add_argument("--whois", help="Perform a Whois lookup.", required=False, action='store_true')
    a.add_argument("-D", "--dns", help="Look for some DNS information", required=False, action='store_true')
    a.add_argument("--spoof", help="Check if domain can be spoofed based on SPF and DMARC records", required=False, action='store_true')
    a.add_argument("-a", "--axfr", help="Try a domain zone transfer attack", required=False, action='store_true')
    a.add_argument("--dork", help="Try some dorks", action='store_true', required=False)
    a.add_argument("-s", "--subdomains", help="Do a search for any subdomain registered", required=False, action='store_true')
    a.add_argument("-p", "--portscan", help="Simple portscan and banner grabbing on top 100 ports (makes a huge noise on the network).", action='store_true', required=False)
    a.add_argument("--subtake", help="Check for subdomain takeover vulnerability", required=False, action='store_true')
    a.add_argument("--ssl", help="Extract information from SSL Certificate.", required=False, action='store_true')
    a.add_argument("-jl", "--js-links", help="Try do find endpoints and parameters in JavaScript files.", required=False, action='store_true')
    a.add_argument("-t", "--tech", help="Try to discover technologies in the page", required=False, action='store_true')
    a.add_argument("-c", "--cors", help="Try to find CORS misconfigurations", required=False, action='store_true')
    a.add_argument("-b", "--backups", help="Try to find some commom backup files in the page. This option works better with -s enabled.", required=False, action='store_true')
    a.add_argument("-w", "--waf", help="Try to detect WAF on the page.", required=False, action='store_true')
    # a.add_argument("--hunt", help="Try to find usefull information about exploiting vectors.", required=False, action='store_true')
    a.add_argument("-r", "--repos", help="Try to discover valid repositories of the domain. This option works better with -s enabled.", action='store_true', required=False)
    a.add_argument("--email", help="Try to find some emails from symem.info. Max 50 emails.", nargs='?', const=50, type=int)
    a.add_argument("--threads", help="Threads (default 5)", type=int, default=5)
    a.add_argument("-V", "--version", help="Show the version", required=False, action='store_true')
    return a.parse_args()


def banner():
    print(f"""
    {GREEN}SWS RECON TOOL
{YELLOW}
⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢠⣾⠿⠟⠛⠳⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠋⠁⢀⠀⢔⣤⡼⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢠⣤⣾⡶⠻⠛⢁⣨⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠉⠉⣀⡴⠆⠂⢐⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣑⠀⢲⡈⠀⢄⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢀⣀⣤⣶⣿⡆⠰⠤⢂⠀⢸⣷⣤⣤⣀⡀⠀⠀⠀
⠀⢠⣾⣿⣿⣿⣿⣿⣇⠀⣾⡗⠀⢸⣿⣿⣿⣿⣿⣷⡀⠀
⠀⣼⣿⣿⣿⣿⣿⣿⣿⠐⣿⣿⠀⢸⣿⣿⣿⣿⣿⣿⣧⠀
⢸⣿⣿⣿⣿⣿⣿⣿⣿⡌⣿⣿⠀⣸⣿⣿⣿⣿⣿⣿⣿⡆
⢸⣿⣿⣿⣿⣿⣿⣿⣿⣇⢻⡟⠀⣿⣿⣿⣿⣿⣿⣿⣿⡇
⠈⠋⠙⠉⠋⠙⠉⠋⠙⠉⠈⠃⠀⠉⠋⠙⠉⠋⠙⠉⠋⠁⠀⠀⠀⠀

      by SecureWithShobhit!
Follow Me On ;)
Github: https://github.com/ShobhitMishra-bot
LinkedIn: https://www.linkedin.com/in/shobhitmishra-learner
          """)

# Check if domain is a valid domain
def validDomain(domain):
    
    try:
        h = socket.gethostbyname(domain)
    except:
        print(f"\n[{YELLOW}!{RESET}] The domain doesn't respond!")
        sys.exit(0)

def write_vulns():

    # print vulnerabilities
    if vulnerability:
        web = []
        infra = []
        if store:
            f = open(dirFile + "/" + domain + ".report.md", "a")
            f.write(f"\n\n## Vulnerabilities found\n")
            for i in vulnerability:
                i = i.split(",")
                if "WEB" in i[0]:
                    web.append(i)
                if "Infra" in i[0]:
                    infra.append(i)

            if infra:
                f.write(f"\n\n### Infra\n\n")
                f.write("| Vulnerability \t\t\t| Confidence \t\t\t| Endpoint \t\t\t| Severity \t\t\t|\n")
                f.write("|" + "-"*47 + "|" + "-"*47 + "|" + "-"*47 + "|" + "-"*47 + "|\n")

                for i in infra:
                    f.write(f"| {i[1]} | {i[2]} | {i[4]} | {i[3]} |\n")

            if web:
                f.write(f"\n\n### WEB\n\n")
                f.write("| Vulnerability \t\t\t| Confidence \t\t\t| Endpoint \t\t\t| Severity \t\t\t|\n")
                f.write("|" + "-"*47 + "|" + "-"*47 + "|" + "-"*47 + "|" + "-"*47 + "|\n")

                for i in web:
                    f.write(f"| {i[1]} | {i[2]} | {i[4]} | {i[3]} |\n")
            f.close()

    if store:
        print(f"\n\n[{GREEN}+{RESET}] Report saved on {GREEN}{dirFile}/{domain}.report.md")


# Program workflow
if __name__ == "__main__":

    banner()
    
    scriptPath = pathlib.Path(__file__).parent.resolve()
    srcPath = str(scriptPath) + "/src/" 
    version = "2.0.1"

    vulnerability = []

    parsing = arguments()

    # threads
    THREADS = parsing.threads
    # max emails to list
    MAX_EMAILS = parsing.email

    # show version
    if parsing.version:
        print(f"\nSWS Recon Tool version: {version}")
        sys.exit(0)
    
    # working with domain
    if not parsing.domain:
        print("\nerror: the following arguments are required: -d/--domain or -h/--help")
        sys.exit(0)
    else:
        domain = parsing.domain
        url_original = domain

    # Cleaning domain input
    if "." not in domain:
        print("\nInvalid domain format, please inform in format: example.com")
        sys.exit(0)
    extracted = tldextract.extract(domain)
    domain = f"{extracted.domain}.{extracted.suffix}"
    validDomain(domain)


    # check if --ouput is passed
    reportPath = ""
    if parsing.output:
        store = 1
        dirFile = str(os.getcwd()) + "/" + domain
        try:
            os.mkdir(dirFile)
        except FileExistsError:
            print(f"[{YELLOW}!{RESET}] The directory {dirFile} already exists!")
            #sys.exit(0)
        reportPath = dirFile + "/" + domain + ".report.md"
        if os.path.isfile(reportPath):
            os.remove(reportPath)
            with open(reportPath, "w") as f:
                f.write(f"# SWS RECON TOOL REPORT FROM {domain.upper()}\n\n")
                f.close()

    else:
        store = 0
        dirFile = ''

    # start scan full
    if parsing.all:
        subs = []
        subt = []
        if parsing.subdomains:
            subs = subDomain(domain, store, reportPath)
            subt = subs
        try:
            whois_lookup(domain, store, reportPath, vulnerability)
            dns_information(domain, store, dirFile, reportPath, vulnerability)
            spoof(domain, vulnerability)
            zone_transfer(domain, store, reportPath, vulnerability)
            portscan(domain, store, reportPath, subs, THREADS)
            if subt:
                subtake(domain, store, subs, reportPath, THREADS)
            ssl_information(domain, store, srcPath, reportPath, subs, THREADS)
            js_links(domain, store, reportPath, subs, THREADS)
            cors(domain, store, reportPath, subs, srcPath, vulnerability, THREADS)
            dorks(domain, store, reportPath)
            find_emails(domain, store, reportPath, MAX_EMAILS, THREADS)
            search_backups(domain, store, reportPath, subs, THREADS)
            tech(domain, store, reportPath, subs, THREADS)
            find_repos(domain, store, reportPath, subs)
            detect_waf(domain, store, reportPath, subs, srcPath, THREADS)
            # hunt(domain, store, reportPath, subs, srcPath, vulnerability, THREADS, url_original)
            write_vulns()
        except KeyboardInterrupt:
            sys.exit(f"[{YELLOW}!{RESET}] Interrupt handler received, exiting...\n")
        sys.exit(0)

    # start scan single option
    subs = []

    try:
        # DNS information
        if parsing.dns:
            dns_information(domain, store, dirFile, reportPath, vulnerability)
        # subdomain enumeration
        if parsing.subdomains:
            subs = subDomain(domain, store, reportPath)
        # subdomain takeover
        if parsing.subtake:
            if not subs:
                subs = subDomain(domain, store, reportPath)
            subtake(domain, store, subs, reportPath, THREADS)
        # Zone transfer attack
        if parsing.axfr:
            zone_transfer(domain, store, reportPath, vulnerability)
        # find repos
        if parsing.repos:
            find_repos(domain, store, reportPath, subs)
        # detect WAF
        if parsing.waf:
            detect_waf(domain, store, reportPath, subs, srcPath, THREADS)
        # Perform whois lookup
        if parsing.whois:
            whois_lookup(domain, store, reportPath, vulnerability)
        # search for backups
        if parsing.backups:
            search_backups(domain, store, reportPath, subs, THREADS)
        # discover technologies
        if parsing.tech:
            tech(domain, store, reportPath, subs, THREADS)
        # HUNT!
        # if parsing.hunt:
        #     hunt(domain, store, reportPath, subs, srcPath, vulnerability, THREADS, url_original)
        # CORS misconfiguration
        if parsing.cors:
            cors(domain, store, reportPath, subs, srcPath, vulnerability, THREADS)
        # DORKS
        if parsing.dork:
            dorks(domain, store, reportPath)
        # Portscan
        if parsing.portscan:
            portscan(domain, store, reportPath, subs, THREADS)
        # E-mail spoof
        if parsing.spoof:
            spoof(domain, vulnerability)
        # Find emails
        if parsing.email:
            find_emails(domain, store, reportPath, MAX_EMAILS, THREADS)
        # SSL certificate information
        if parsing.ssl:
            ssl_information(domain, store, srcPath, reportPath, subs, THREADS)
        # JS links
        if parsing.js_links:
            js_links(domain, store, reportPath, subs, THREADS)
    except KeyboardInterrupt:
        sys.exit(f"[{YELLOW}!{RESET}] Interrupt handler received, exiting...\n")

    write_vulns()
