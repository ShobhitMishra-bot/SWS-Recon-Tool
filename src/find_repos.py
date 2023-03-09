import requests
from time import sleep
from src.colors import YELLOW, GREEN, RED, BLUE, RESET

import urllib3
import warnings
urllib3.disable_warnings()
warnings.simplefilter("ignore")

# Find repos function
def find_repos(domain, store, reportPath, subs):

    print(f"\n{BLUE}[*] Looking for public repositories...\n")
    sleep(0.2)

    if domain not in subs:
        subs.append(domain)

    git_repo = []
    git = []
    bit = []
    gitlab = []
    for i in subs:
        try:
            URL = f"https://{i}/.git/"
            r = requests.get(URL, verify=False, timeout=10)
            if f"{URL},{str(r.status_code)}" not in git_repo:
                git_repo.append(f"{URL},{str(r.status_code)}")
            print(f"[{GREEN}+{RESET}] Git directory in {URL} responds with {str(r.status_code)} status code.")
        except:
            pass

    try:
        URL = f"https://bitbucket.org/{domain.split('.')[0]}"
        r = requests.get(URL, verify=False, timeout=20)
        bit.append(f"{URL},{r.status_code}")
        print(f"[{GREEN}+{RESET}] Bitbucket repository in {URL} responds with {str(r.status_code)} status code.")
    except:
        pass

    try:
        URL = f"https://github.com/{domain.split('.')[0]}"
        r = requests.get(URL, verify=False, timeout=20)
        if str(r.status_code) == "200":
            git.append(f"{URL},{r.status_code}")
            print(f"[{GREEN}+{RESET}] Github repository in {URL} responds with {str(r.status_code)} status code.")
    except:
        pass

    try:
        URL = f"https://gitlab.com/{domain.split('.')[0]}"
        r = requests.get(URL, verify=False, timeout=20)
        if str(r.status_code) == "200":
            gitlab.append(f"{URL},{r.status_code}")
            print(f"[{GREEN}+{RESET}] Gitlab repository in {URL} responds with {str(r.status_code)} status code.")
    except:
        pass

    if git_repo or bit or git or gitlab:
        if store:
            f = open(reportPath, "a")
            f.write(f"\n\n## Public repositories from {domain}\n\n")

            if git_repo:
                f.write("### Git repositories:\n\n")
                f.write("|" + " URL \t\t\t\t| STATUS \t\t\t|\n" + "|" + "-" *47 + "|" + "-" *23 + "|\n")
                for i in git_repo:
                    f.write(f"| {i.split(',')[0]} | {i.split(',')[1]} |\n")
                f.write("\n\n")

            if bit:
                f.write("### Bitbucket repositories:\n\n")
                f.write("|" + " URL \t\t\t\t| STATUS \t\t\t|\n" + "|" + "-" *47 + "|" + "-" *23 + "|\n")
                for i in bit:
                    f.write(f"| {i.split(',')[0]} | {i.split(',')[1]} |\n")
                f.write("\n\n")

            if git:
                f.write("### GitHub repositories:\n\n")
                f.write("|" + " URL \t\t\t\t| STATUS \t\t\t|\n" + "|" + "-" *47 + "|" + "-" *23 + "|\n")
                for i in git:
                    f.write(f"| {i.split(',')[0]} | {i.split(',')[1]} |\n")
                f.write("\n\n")

            if gitlab:
                f.write("### GitLab repositories:\n\n")
                f.write("|" + " URL \t\t\t\t| STATUS \t\t\t|\n" + "|" + "-" *47 + "|" + "-" *23 + "|\n")
                for i in gitlab:
                    f.write(f"| {i.split(',')[0]} | {i.split(',')[1]} |\n")
                f.write("\n\n")

        if store:
            f.close()