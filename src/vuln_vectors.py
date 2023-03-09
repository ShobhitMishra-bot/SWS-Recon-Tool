import re
import requests
import json
import sys
from time import sleep
from urllib.parse import urljoin
from bs4 import BeautifulSoup as bs
from src.colors import YELLOW, GREEN, RED, BLUE, RESET

import urllib3
import warnings
urllib3.disable_warnings()
warnings.simplefilter("ignore")

# threading
try:
    import concurrent.futures
except ImportError:
    print(f"[{YELLOW}!{RESET}] SWS needs python 3.4 > ro run!")
    sys.exit()

def sqli_form(f, errors):
    data = {}

    try:
        # get target URL
        action = f.attrs.get("action").lower()
    except Exception as e:
        action = None

    # get the form method
    method = f.attrs.get("method", "get").lower()

    # get datils from form
    details = []
    for tag in f.find_all("input"):
        in_type = tag.attrs.get("type", "text")
        name = tag.attrs.get("name")
        value = tag.attrs.get("value", "")
        details.append({"type": in_type, "name": name, "value": value})

    # returning values
    data["action"] = action
    data["method"] = method
    data["details"] = details

    return data


# request xss function
def request_xss(endpoint, references, vulnerability):
    xss = []

    for p in references["XSS"]:
        if re.findall(rf".*{p}.*?", endpoint):
            xss_url = re.findall(rf".*{p}.*?", endpoint)[0] + "XSS"
            if xss_url not in xss:
                xss.append(xss_url)
    if xss:
        for i in xss:
            print(f"[{GREEN}+{RESET}] Possible XSS vector found in: {GREEN}{i}\n")
            vulnerability.append(
                f"WEB, XSS Reflected, Possible, [6.1](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N), URL: {i}")
        return xss
    else:
        return None


# request json function
def request_json(endpoint, vulnerability):
    json_file = []

    if ".json" in endpoint and endpoint not in json_file:
        json_file.append(endpoint)
    if json_file:
        for i in json_file:
            print(f"[{GREEN}+{RESET}] Json file found in: {GREEN}{i}\n")
            vulnerability.append(
                f"WEB, Information Disclosure, Possible, [3.7](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N), URL: {i}")
        return json_file
    else:
        return None


# request open redirect function
def request_or(endpoint, references, vulnerability):
    or_file = []

    for p in references["REDIRECTS"]:
        if re.findall(rf".*{p}.*?", endpoint):
            red_url = re.findall(rf".*{p}.*?", endpoint)[0] + "OPEN-REDIRECT"
            if red_url not in or_file:
                or_file.append(red_url)
    if or_file:
        for i in or_file:
            print(f"[{GREEN}+{RESET}] Possible open redirect vector found in: {GREEN}{i}\n")
            vulnerability.append(
                f"WEB, Open Redirect, Possible, [4.3](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N), URL: {i}")
        return or_file
    else:
        return None


# request SQLi in URL function
def request_sqli_url(endpoint, sql_errors, vulnerability):
    sqli_file = []

    # test on URL
    for p in "\"'":
        if "=" in endpoint:
            endpoint = endpoint.split("=")[0] + f"={p}"
            try:
                r = requests.get(endpoint, timeout=4).text
                for db, errors in sql_errors.items():
                    for error in errors:
                        if re.compile(error).search(r):
                            sqli_file.append(endpoint)
                            vulnerability.append(
                                f"WEB, SQLi - {db}, Possible, [8.6](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N, URL: {endpoint})")
                            print(f"[{GREEN}+{RESET}] Possible SQLi vector in db {db} in: {endpoint}")

            except:
                pass


# request SQLi in URL function
def request_sqli_forms(subdomain, sql_errors, vulnerability):
    sqli_file = []

    # test on forms

    forms = ""

    schemas = ["http://", "https://"]
    for schema in schemas:
        try:
            soup = bs(requests.get(f"{schema}{subdomain}", timeout=4, verify=False).content, "html.parser",
                      from_encoding="iso-8859-1")
            forms = soup.find_all("form")
        except Exception as e:
            continue

        if forms:
            for f in forms:
                details = sqli_form(f, sql_errors)

                for p in "\"'":

                    # body to request
                    body = {}

                    for tag in details["details"]:
                        if tag["value"] or tag["type"] == "hidden":
                            try:
                                body[tag["name"]] = tag["value"] + p
                            except:
                                pass
                        elif tag["type"] != "submit":
                            body[tag["name"]] = f"SWS{p}"

                    # join url with action
                    URL = urljoin(f"{schema}{subdomain}", details["action"])
                    if details["method"] == "post":
                        request = f"{URL}, POST"
                        r = requests.post(URL, data=body, verify=False, timeout=4).text
                    elif details["method"] == "get":
                        request = f"{URL}, GET"
                        r = requests.get(URL, params=body, verify=False, timeout=4).text

                    # test for errors
                    for db, errors in sql_errors.items():
                        for error in errors:
                            if re.compile(error).search(r):
                                sqli_file.append("{request[0]}, {request[1]}")
                                vulnerability.append(
                                    f"WEB, SQLi - {db}, Possible, [8.6](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N, URL: {schema}{subdomain})")
                                print(f"[{GREEN}+{RESET}] Possible SQLi vector in db {db} in: {subdomain}")

    if sqli_file:
        return sqli_file
    else:
        return None


# hunt information function
def hunt(domain, store, reportPath, subs, srcPath, vulnerability, THREADS, url_original):
    print(f"\n{BLUE}[*] Searching for usefull information...\n")
    sleep(0.2)
    if domain not in subs:
        subs.append(domain)

    # get json references
    try:
        r = requests.get("https://raw.githubusercontent.com/h41stur/SWS/main/src/references_recon.json", verify=False,
                         timeout=10)
        references = json.loads(r.text)
    except:
        with open(srcPath + "references_recon.json", "r") as file:
            references = json.load(file)

    sql_errors = {
        "MySQL": (r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"MySQL Query fail.*", r"SQL syntax.*MariaDB server"),
        "PostgreSQL": (r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"Warning.*PostgreSQL"),
        "Microsoft SQL Server": (
        r"OLE DB.* SQL Server", r"(\W|\A)SQL Server.*Driver", r"Warning.*odbc_.*", r"Warning.*mssql_",
        r"Msg \d+, Level \d+, State \d+", r"Unclosed quotation mark after the character string",
        r"Microsoft OLE DB Provider for ODBC Drivers"),
        "Microsoft Access": (r"Microsoft Access Driver", r"Access Database Engine", r"Microsoft JET Database Engine",
                             r".*Syntax error.*query expression"),
        "Oracle": (
        r"\bORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Warning.*oci_.*", "Microsoft OLE DB Provider for Oracle"),
        "IBM DB2": (r"CLI Driver.*DB2", r"DB2 SQL error"),
        "SQLite": (r"SQLite/JDBCDriver", r"System.Data.SQLite.SQLiteException"),
        "Informix": (r"Warning.*ibase_.*", r"com.informix.jdbc"),
        "Sybase": (r"Warning.*sybase.*", r"Sybase message")
    }

    endpoints = []
    edp_xss = []
    edp_json = []
    edp_red = []
    edp_sqli = []

    for s in subs:
        # Consulting wayback machine
        try:
            r = requests.get(
                f"http://web.archive.org/cdx/search/cdx?url=*.{s}/*&output=json&fl=original&collapse=urlkey",
                timeout=10)
            resp = r.json()
            resp = resp[1:]
            for i in resp:
                if i[0] not in endpoints:
                    endpoints.append(i[0])
        except Exception as e:
            pass

        # Consulting URLScan
        try:
            r = requests.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}", timeout=10)
            resp = json.loads(r.text)
            resp = resp["results"]
            for i in resp:
                i = i["task"]["url"]
                if i not in endpoints:
                    endpoints.append(i)
        except Exception as e:
            pass

    # iterating on endpoints
    if endpoints:

        pool = concurrent.futures.ThreadPoolExecutor(max_workers=THREADS)
        # try to find xss vectors
        print(f"[{BLUE}*{RESET}] Searching for XSS vectors...\n")
        data = (pool.submit(request_xss, e, references, vulnerability) for e in endpoints)
        for resp in concurrent.futures.as_completed(data):
            resp = resp.result()
            if resp is not None and resp not in edp_xss:
                edp_xss.append(resp)
        if not edp_xss:
            print(f"\t[{RED}-{RESET}] No XSS vectors found!")

        # try to find usefull json files
        print(f"\n[{BLUE}*{RESET}] Searching for usefull json files...\n")
        data = (pool.submit(request_json, e, vulnerability) for e in endpoints)
        for resp in concurrent.futures.as_completed(data):
            resp = resp.result()
            if resp is not None and resp not in edp_json:
                edp_json.append(resp)
        if not edp_json:
            print(f"\t[{RED}-{RESET}] No json file found!")

        # try to find open redirects
        print(f"\n[{BLUE}*{RESET}] Searching for open redirect vectors...\n")
        data = (pool.submit(request_or, e, references, vulnerability) for e in endpoints)
        for resp in concurrent.futures.as_completed(data):
            resp = resp.result()
            if resp is not None and resp not in edp_red:
                edp_red.append(resp)
        if not edp_red:
            print(f"\t[{RED}-{RESET}] No open redirect vectors found!")

        # try to find SQLi in URL
        print(f"\n[{BLUE}*{RESET}] Searching for SQLi in URLs...\n")
        data = (pool.submit(request_sqli_url, e, sql_errors, vulnerability) for e in endpoints)
        for resp in concurrent.futures.as_completed(data):
            resp = resp.result()
            if resp is not None and resp not in edp_sqli:
                edp_sqli.append(resp)

        # try to find SQLi in forms
        print(f"[{BLUE}*{RESET}] Searching for SQLi in forms...\n")
        try:
            url_sqli = url_original.split("://")[1]
        except:
            url_sqli = url_original

        subs_sqli = subs

        if url_sqli not in subs_sqli:
            subs_sqli.append(url_sqli)

        data = (pool.submit(request_sqli_forms, s, sql_errors, vulnerability) for s in subs_sqli)
        for resp in concurrent.futures.as_completed(data):
            resp = resp.result()
            if resp is not None and resp not in edp_sqli:
                edp_sqli.append(resp)

        if not edp_sqli:
            print(f"\t[{RED}-{RESET}] No SQLi vectors found!")

        # preparing report
        if store:
            f = open(reportPath, "a")
            if edp_xss or edp_json or edp_red or edp_sqli:
                f.write(f"\n\n## Usefull information\n\n")

            if edp_xss:
                f.write(f"\n\n### Possible XSS vectors\n\n")
                f.write("| URL \t\t\t\t|\n|" + "-" * 47 + "|\n")
                for e in edp_xss:
                    for i in e:
                        f.write(f"| {i} |\n")

            if edp_json:
                f.write(f"\n\n### Json files\n\n")
                f.write("| URL \t\t\t\t|\n|" + "-" * 47 + "|\n")
                for i in edp_json:
                    f.write(f"| {i} |")

            if edp_red:
                f.write(f"\n\n### Possible open redirect vectors\n\n")
                f.write("| URL \t\t\t\t|\n|" + "-" * 47 + "|\n")
                for i in edp_red:
                    f.write(f"| {i} |")

            if edp_sqli:
                f.write(f"\n\n### Possible SQLi vectors\n\n")
                f.write("| URL \t\t\t\t| METHOD |\n|" + "-" * 47 + "|" + "-" * 47 + "|\n")
                for i in edp_sqli:
                    i = i.split(",")
                    f.write(f"| {i[0]} | {i[1]} |\n")

            f.close()


    else:
        print(f"[{RED}-{RESET}] No information found")
