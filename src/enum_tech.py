import json
import sys
from time import sleep
from src.colors import YELLOW, GREEN, RED, BLUE, RESET

# threading
try:
    import concurrent.futures
except ImportError:
    print(f"[{YELLOW}!{RESET}] SWS needs python 3.4 > ro run!")
    sys.exit()

# request tech function
def request_tech(subdomain):
    schemas = ["https://", "http://"]
    techs = []

    try:
        from Wappalyzer import Wappalyzer, WebPage
        wapp = Wappalyzer.latest()
        for schema in schemas:
            web = WebPage.new_from_url(f"{schema}{subdomain}", verify=False)
            tech = wapp.analyze_with_versions(web)

            if tech != "{}":
                file = json.loads(json.dumps(tech, sort_keys=True, indent=4))
                print(f"[{GREEN}+{RESET}] {schema}{subdomain}")
                for i in file:
                    try:
                        version = file[i]['versions'][0]
                    except:
                        version = "Version not found!"
                    if f"{subdomain},{i},{version}" not in techs:
                        techs.append(f"{subdomain},{i},{version}")
                    print(f"\t{GREEN}-{RESET} {i}: {version}")
                print("\n")
            else:
                print(f"[{RED}-{RESET}] No common technologies found")
    except Exception as e:
        print(f"[{RED}-{RESET}] An error has ocurred or unable to enumerate {subdomain}")

    if techs:
        return techs
    else:
        return None


# Discover technologies function
def tech(domain, store, reportPath, subs, THREADS):
    print(f"\n{BLUE}[*] Searching for technologies...\n")
    sleep(0.2)
    if domain not in subs:
        subs.append(domain)
    techsWeb = []

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=THREADS)
    data = (pool.submit(request_tech, s) for s in subs)
    for resp in concurrent.futures.as_completed(data):
        resp = resp.result()
        if resp is not None and resp not in techsWeb:
            techsWeb.append(resp)

    if techsWeb:

        if store:
            f = open(reportPath, "a")
            f.write(f"\n\n## Common technologies found\n\n")
            f.write(
                "|" + " URL \t\t\t\t| TECHNOLOGY \t\t\t| VERSION \t\t\t|\n" + "|" + "-" * 47 + "|" + "-" * 23 + "|" + "-" * 23 + "|\n")
            for tech in techsWeb:
                for i in tech:
                    i = i.split(",")
                    u = i[0]
                    t = i[1]
                    v = i[2]
                    f.write(f"| {u} | {t} | {v} |\n")
            f.close()
