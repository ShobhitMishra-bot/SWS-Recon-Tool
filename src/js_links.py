import re
import sys
import html
import jsbeautifier
import ssl
from time import sleep
from gzip import GzipFile
from src.colors import YELLOW, GREEN, RED, BLUE, RESET

# threading
try:
    import concurrent.futures
except ImportError:
    print(f"[{YELLOW}!{RESET}] SWS needs python 3.4 > ro run!")
    sys.exit()

import urllib3
import warnings
urllib3.disable_warnings()
warnings.simplefilter("ignore")

try:
    from StringIO import StringIO
    readBytesCustom = StringIO
except ImportError:
    from io import BytesIO
    readBytesCustom = BytesIO

try:
    from urllib.request import Request, urlopen
except ImportError:
    from urllib3 import Request, urlopen

context = ssl._create_unverified_context()

regex = r"""
  (?:"|')                               # Start newline delimiter
  (
    ((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
    [^"'/]{1,}\.                        # Match a domainname (any character + dot)
    [a-zA-Z]{2,}[^"']{0,})              # The domainextension and/or path
    |
    ((?:/|\.\./|\./)                    # Start with /,../,./
    [^"'><,;| *()(%%$^/\\\[\]]          # Next character can't be...
    [^"'><,;|()]{1,})                   # Rest of the characters can't be
    |
    ([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
    [a-zA-Z0-9_\-/]{1,}                 # Resource name
    \.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
    (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters
    |
    ([a-zA-Z0-9_\-/]{1,}/               # REST API (no extension) with /
    [a-zA-Z0-9_\-/]{3,}                 # Proper REST endpoints usually have 3+ chars
    (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters
    |
    ([a-zA-Z0-9_\-]{1,}                 # filename
    \.(?:php|asp|aspx|jsp|json|
         action|html|js|txt|xml)        # . + extension
    (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters
  )
  (?:"|')                               # End newline delimiter
"""

def request_url(u):

    r = Request(u)
    r.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36')
    r.add_header('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8')
    r.add_header('Accept-Language', 'en-US,en;q=0.8')
    r.add_header('Accept-Encoding', 'gzip')

    resp = urlopen(r, timeout=4, context=context)

    if resp.info().get('Content-Encoding') == 'gzip':
        js = GzipFile(fileobj=readBytesCustom(resp.read())).read()
    elif resp.info().get('Content-Encoding') == 'deflate':
        js = resp.read().read()
    else:
        js = resp.read()

    return js.decode('utf-8', 'replace')

def parsing_js(js, regex):

    content = jsbeautifier.beautify(js)

    rgx = re.compile(regex, re.VERBOSE)

    elements = [{"link": m.group(1)} for m in re.finditer(rgx, content)]
    clean_links = []
    for e in elements:
        if e["link"] not in clean_links:
            clean_links.append(e)
    elements = clean_links

    return elements


def execution(u):

    endpoints = []

    for schema in ('https://', 'http://'):
        url = f"{schema}{u}"
        try:
            js = request_url(url)
            edp = parsing_js(js, regex)

            for e in edp:
                url_js = html.escape(e["link"]).encode(
                'ascii', 'ignore').decode('utf8')
                if url_js not in endpoints:
                    endpoints.append(url_js)
        except:
            pass
    if endpoints:
        print(f"\n[{GREEN}+{RESET}] {u}\n")
        for e in endpoints:
            print(f"\t{GREEN}-{RESET} {e}")
        return {u: endpoints}


def js_links(domain, store, reportPath, subs, THREADS):

    print(f"\n{BLUE}[*] Searching for endpoints in JS files...\n")
    sleep(0.2)
    if domain not in subs:
        subs.append(domain)

    endpoints = []

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=THREADS)
    data = (pool.submit(execution, s) for s in subs)
    for resp in concurrent.futures.as_completed(data):
        resp = resp.result()
        if resp is not None and resp not in endpoints:
            endpoints.append(resp)

    if endpoints:

        if store:
            f = open(reportPath, "a")
            f.write(f"\n\n## Endpoints and parameters in JavaScript\n\n")
            for e in endpoints:
                for k, v in e.items():
                    f.write(f"\n\n### Endpoints and parameters from **{k}**\n\n")
                    for i in v:
                        f.write(f"- {i}\n")
            f.close()

    else:
        print(f"[{YELLOW}!{RESET}] No endpoints or parameters found.")








