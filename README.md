# SWS Recon Tool	

##  📌 Introduction
SWS-Recon is a Python Tool designed to performed Reconnaissance on the given target website- `Domain` or `SubDomain`. SWS-Recon collects information such as Google Dork, DNS Information, Sub Domains, PortScan, Subdomain takeovers, Reconnaissance On Github and much more vulnerability scan.

## 💥 Main Features

:heavy_check_mark: Perform a Whois lookup.

:heavy_check_mark: Search for useful DNS information.

:heavy_check_mark: Search for email spoofing vulnerability.

:heavy_check_mark: Domain zone transfer attack.

:heavy_check_mark: Perform Google dorks.

:heavy_check_mark: Search for subdomains.

:heavy_check_mark: Perform portscan.

:heavy_check_mark: Check for subdomain takeover.

:heavy_check_mark: Ennumerate some techs on pages.

:heavy_check_mark: Check for CORS misconfiguration.

:heavy_check_mark: Search for common backup files.

:heavy_check_mark: Try to detect WAF.

:heavy_check_mark: Check for common vulnerabilities, like SQLi, XSS and Open Redirect.

:heavy_check_mark: Search for git repos.

:heavy_check_mark: Search for employees emails.

## ⚡ Installation
```
git clone https://github.com/ShobhitMishra-bot/SWS-Recon-Tool.git
cd SWS-Recon-Tool
python3 -m pip3 install -r requirements.txt
```
## Usage

```bash
python3 SWS-Recon.py -h
```
Help display as and guide to use other tool features-
```
    SWS RECON TOOL

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
          
usage: SWS-Recon.py [-h] [-d DOMAIN] [-o] [-A] [--whois] [-D] [--spoof] [-a]
                    [--dork] [-s] [-p] [--subtake] [--ssl] [-jl] [-t] [-c]
                    [-b] [-w] [-r] [--email [EMAIL]] [--threads THREADS] [-V]

SWS Recon Tool

options:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Domain to start recon
  -o, --output          Save a directory containing Markdown file with recon
                        report.
  -A, --all             Permorm all options at once, except -s and -o (which
                        can be added manually)
  --whois               Perform a Whois lookup.
  -D, --dns             Look for some DNS information
  --spoof               Check if domain can be spoofed based on SPF and DMARC
                        records
  -a, --axfr            Try a domain zone transfer attack
  --dork                Try some dorks
  -s, --subdomains      Do a search for any subdomain registered
  -p, --portscan        Simple portscan and banner grabbing on top 100 ports
                        (makes a huge noise on the network).
  --subtake             Check for subdomain takeover vulnerability
  --ssl                 Extract information from SSL Certificate.
  -jl, --js-links       Try do find endpoints and parameters in JavaScript
                        files.
  -t, --tech            Try to discover technologies in the page
  -c, --cors            Try to find CORS misconfigurations
  -b, --backups         Try to find some commom backup files in the page. This
                        option works better with -s enabled.
  -w, --waf             Try to detect WAF on the page.
  -r, --repos           Try to discover valid repositories of the domain. This
                        option works better with -s enabled.
  --email [EMAIL]       Try to find some emails from symem.info. Max 50
                        emails.
  --threads THREADS     Threads (default 5)
  -V, --version         Show the version
```


## ❤️ Contribution
You can contribute in following ways:

- Report bugs
- Develop tool
- Give suggestions to make it better
- Fix issues & submit a pull request
