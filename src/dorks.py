import tldextract
import requests
import sys
from time import sleep
from googlesearch import search
from src.colors import YELLOW, GREEN, RED, BLUE, RESET

import urllib3
import warnings
urllib3.disable_warnings()
warnings.simplefilter("ignore")

# Dorks function
def dorks(domain, store, reportPath):
    print(f"\n{BLUE}[*] Dorking...")

    links = {}
    target = tldextract.extract(str(domain)).domain

    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36"


    terms = {
        ".git folders": f"inurl:\"/.git\" {domain} -github",
        "Backup files": f"site:{domain} ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup",
        "Exposed documents": f"site:{domain} ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv",
        "Confidential documents": f"inurl:{target} not for distribution | confidential | \"employee only\" | proprietary | top secret | classified | trade secret | internal | private filetype:xls OR filetype:csv OR filetype:doc OR filetype:pdf",
        "Config files": f"site:{domain} ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:env | ext:ini",
        "Database files": f"site:{domain} ext:sql | ext:dbf | ext:mdb",
        "Other files": f"site:{domain} intitle:index.of | ext:log | ext:php intitle:phpinfo \"published by the PHP Group\" | inurl:shell | inurl:backdoor | inurl:wso | inurl:cmd | shadow | passwd | boot.ini | inurl:backdoor | inurl:readme | inurl:license | inurl:install | inurl:setup | inurl:config | inurl:\"/phpinfo.php\" | inurl:\".htaccess\" | ext:swf",
        "SQL errors": f"site:{domain} intext:\"sql syntax near\" | intext:\"syntax error has occurred\" | intext:\"incorrect syntax near\" | intext:\"unexpected end of SQL command\" | intext:\"Warning: mysql_connect()\" | intext:\"Warning: mysql_query()\" | intext:\"Warning: pg_connect()\"",
        "PHP errors": f"site:{domain} \"PHP Parse error\" | \"PHP Warning\" | \"PHP Error\"",
        "Wordpress files": f"site:{domain} inurl:wp-content | inurl:wp-includes",
        "Project management sites": f"site:trello.com | site:*.atlassian.net \"{target}\"",
        "GitLab/GitHub/Bitbucket": f"site:github.com | site:gitlab.com | site:bitbucket.org \"{target}\"",
        "Cloud buckets S3/GCP": f"site:.s3.amazonaws.com | site:storage.googleapis.com | site:amazonaws.com \"{target}\"",
        "Traefik": f"intitle:traefik inurl:8080/dashboard \"{target}\"",
        "Jenkins": f"intitle:\"Dashboard [Jenkins]\" \"{target}\"",
        "Login pages": f"site:{domain} inurl:signup | inurl:register | intitle:Signup",
        "Open redirects": f"site:{domain} inurl:redir | inurl:url | inurl:redirect | inurl:return | inurl:src=http | inurl:r=http",
        "Code share sites": f"site:sharecode.io | site:controlc.com | site:codepad.co |site:ideone.com | site:codebeautify.org | site:jsdelivr.com | site:codeshare.io | site:codepen.io | site:repl.it | site:jsfiddle.net \"{target}\"",
        "Other 3rd parties sites": f"site:gitter.im | site:papaly.com | site:productforums.google.com | site:coggle.it | site:replt.it | site:ycombinator.com | site:libraries.io | site:npm.runkit.com | site:npmjs.com | site:scribd.com \"{target}\"",
        "Stackoverflow": f"site:stackoverflow.com \"{domain}\"",
        "Pastebin-like sites": f"site:justpaste.it | site:heypasteit.com | site:pastebin.com \"{target}\"",
        "Apache Struts RCE": f"site:{domain} ext:action | ext:struts | ext:do",
        "Linkedin employees": f"site:linkedin.com employees {domain}",
    }

    r = requests.get('https://google.com', verify=False)

    for title, dork in terms.items():
        result = []
        try:
            for r in search(dork,
                            user_agent=user_agent,
                            tld="com", lang="en", num=10, start=0, stop=None, pause=2):
                if r not in result:
                    result.append(r)
            sleep(10)
            if result:
                print(f"\n[{BLUE}*{RESET}] {title}")
                for i in result:
                    print(f"\t{GREEN}-{RESET} {i}")
                links[title] = result
        except KeyboardInterrupt:
            sys.exit(f"[{YELLOW}!{RESET}] Interrupt handler received, exiting...\n")
        except Exception as e:
            if "429" in str(e):
                print(f"[{YELLOW}!{RESET}] Too many requests, unable to obtain a response from Google.")
                break
            pass


        sleep(10)

    if links:
        if store:
            f = open(reportPath, "a")
            f.write(f"\n\n## Dork links\n\n")
            for l in links:
                f.write(f"\n\n### {l}\n")
                for i in links[l]:
                    f.write(f"\n\t- {i}")
            f.close()
    else:
        print(f"[{YELLOW}!{RESET}] No results.")