import os
import sys
import time
import logging
import argparse
import re
import urllib.parse
import requests
import concurrent.futures
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from bs4 import BeautifulSoup
from collections import deque
import yaml
import json
import random

# For optional screenshots
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.common.exceptions import TimeoutException, WebDriverException

###############################################################################
# Logging
###############################################################################
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger("ghost_osint")

###############################################################################
# Terminal Colors
###############################################################################
GREEN = '\033[92m'
RESET = '\033[0m'
CYAN = '\033[96m'
RED = '\033[91m'
BOLD = '\033[1m'

###############################################################################
# Banner
###############################################################################
def print_banner():
    banner = (
        f"{BOLD}{RED}"
        "   _____ __                __  ____  ___________\n"
        "  / ___// /___  __  ______/ /_/ __ \\/ ____/ ___/\n"
        "  \\__ \\/ / __ \\/ / / / __  / / /_/ / __/  \\__ \\\n"
        " ___/ / / /_/ / /_/ / /_/ / / ____/ /___ ___/ /\n"
        "/____/_/\\____/\\__,_/\\__,_/_/_/   /_____//____/ \n"
        f"       Advanced Bug Bounty Crawler (Txt Patterns)\n"
        f"{RESET}"
    )
    print(banner)

###############################################################################
# Load config.yaml
###############################################################################
def load_config():
    try:
        with open("config.yaml", 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        logger.error(f"{RED}config.yaml not found!{RESET}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"{RED}[ERROR] Failed to load config.yaml: {e}{RESET}")
        sys.exit(1)

###############################################################################
# Load Patterns from .txt files
###############################################################################
def load_patterns(directory="wordlists"):
    """
    Reads patterns from 7 separate text files in the given 'directory'.
    Each file has one pattern per line. Returns a dict with lists.
    """
    files_map = {
        "query_params": "query_params.txt",
        "api_wss": "api_wss.txt",
        "common_misconfig": "common_misconfig.txt",
        "injection_points": "injection_points.txt",
        "sensitive_data": "sensitive_data.txt",
        "exposed_files": "exposed_files.txt",
        "js_vulnerabilities": "js_vulnerabilities.txt"
    }

    patterns = {
        "query_params": [],
        "api_wss": [],
        "common_misconfig": [],
        "injection_points": [],
        "sensitive_data": [],
        "exposed_files": [],
        "js_vulnerabilities": []
    }

    for key, filename in files_map.items():
        path = os.path.join(directory, filename)
        if not os.path.isfile(path):
            logger.warning(f"{RED}[WARN] Missing pattern file: {path}{RESET}")
            continue

        with open(path, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f if line.strip()]
            patterns[key] = lines

    return patterns

###############################################################################
# Create Requests Session
###############################################################################
def create_session(config):
    """
    Creates a requests.Session with random UA from config,
    plus optional SSL verification.
    """
    session = requests.Session()

    # 1) Get user-agents from config, or fallback
    crawler_cfg = config.get("crawler", {})
    user_agents = crawler_cfg.get("user_agents", [
        # fallback default list if user_agents not in config.yaml
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2_3) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/90.0.4430.24 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1"
    ])
    session.headers.update({"User-Agent": random.choice(user_agents)})

    # 2) Retry config
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    # 3) SSL verify
    session.verify = crawler_cfg.get("verify_ssl", True)

    return session

###############################################################################
# BFS Constraints
###############################################################################
def get_spider_constraints(config):
    web_cfg = config.get("web", {})
    distance = web_cfg.get("spider_distance", 2)
    depth = web_cfg.get("spider_depth", 4)
    links_per_page = web_cfg.get("spider_links_per_page", 25)
    return distance, depth, links_per_page

###############################################################################
# Recon Data
###############################################################################
def init_recon_data():
    return {
        "fetched_urls": set(),
        "external_links": set(),
        "subdomains": set(),
        "emails": set(),
        "phones": set(),
        "potential_phones": [],  # (url, snippet)
        "socials": set(),
        "interesting_pages": set(),
        "parameters": set()  # (url, param)
    }

###############################################################################
# Vulnerability Data
###############################################################################
def init_vuln_data():
    return {
        "query_params": [],
        "api_wss": [],
        "common_misconfig": [],
        "injection_points": [],
        "sensitive_data": [],
        "exposed_files": [],
        "js_vulnerabilities": []
    }

###############################################################################
# Patterns for normal recon
###############################################################################
EMAIL_REGEX = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
PHONE_PLUS_REGEX = re.compile(r'\+\d[\d\s-]+')
POTENTIAL_PHONE_REGEX = re.compile(r'(\d{3}\s\d{2}\s\d{3})')
INTERESTING_KEYWORDS = ["login", "signup", "signin", "admin", "dashboard"]

SOCIAL_DOMAINS = [
    "instagram.com",
    "facebook.com",
    "twitter.com",
    "linkedin.com",
    "discord.gg",
    "t.me",
    "youtube.com",
    "snapchat.com",
    "pinterest.com",
    "reddit.com"
]

###############################################################################
# BFS Helpers
###############################################################################
def is_subdomain(host, base_domain):
    return (host != base_domain) and host.endswith("." + base_domain)

def is_interesting_page(url):
    return any(kw in url.lower() for kw in INTERESTING_KEYWORDS)

def fetch_page(session, url, timeout=8):
    try:
        resp = session.get(url, timeout=timeout)
        return resp, None
    except Exception as e:
        return None, e

###############################################################################
# In-Place Status
###############################################################################
def init_live_display():
    print("Queue:            [0]")
    print("Fetched URLs:     [0]")
    print("Subdomains:       [0]")
    print("Emails:           [0]")
    print("Phones:           [0]")
    print("Socials:          [0]")
    print("Interesting:      [0]")
    print("PotentialPhones:  [0]")
    sys.stdout.flush()

def update_live_display(
    queue_len,
    fetched_count,
    subdomains_count,
    emails_count,
    phones_count,
    socials_count,
    interesting_count,
    potential_phone_count
):
    print("\033[8A", end="")
    print(f"\033[KQueue:            [{queue_len}]")
    print(f"\033[KFetched URLs:     [{fetched_count}]")
    print(f"\033[KSubdomains:       [{subdomains_count}]")
    print(f"\033[KEmails:           [{emails_count}]")
    print(f"\033[KPhones:           [{phones_count}]")
    print(f"\033[KSocials:          [{socials_count}]")
    print(f"\033[KInteresting:      [{interesting_count}]")
    print(f"\033[KPotentialPhones:  [{potential_phone_count}]")
    sys.stdout.flush()

###############################################################################
# BFS Crawler
###############################################################################
def crawl_website(base_url, distance, depth, links_per_page, threads, config, recon_data, vuln_data, patterns):
    session = create_session(config)
    visited = set()
    parsed_base = urllib.parse.urlparse(base_url)
    base_domain = parsed_base.netloc

    queue = deque([(base_url, 0)])
    init_live_display()
    last_update = time.time()

    while queue:
        now = time.time()
        if now - last_update >= 3:
            update_live_display(
                len(queue),
                len(recon_data["fetched_urls"]),
                len(recon_data["subdomains"]),
                len(recon_data["emails"]),
                len(recon_data["phones"]),
                len(recon_data["socials"]),
                len(recon_data["interesting_pages"]),
                len(recon_data["potential_phones"])
            )
            last_update = now

        # Grab a batch
        batch = []
        while queue and len(batch) < threads:
            batch.append(queue.popleft())

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_item = {}
            for (the_url, dist_now) in batch:
                if the_url not in visited:
                    future = executor.submit(fetch_page, session, the_url, 8)
                    future_to_item[future] = (the_url, dist_now)

            for future in concurrent.futures.as_completed(future_to_item):
                (current_url, current_dist) = future_to_item[future]
                visited.add(current_url)
                recon_data["fetched_urls"].add(current_url)

                resp, err = future.result()
                if resp and resp.status_code == 200:
                    parse_page(
                        current_url,
                        resp,
                        base_domain,
                        recon_data,
                        vuln_data,
                        patterns
                    )
                    if current_dist < distance:
                        new_links = extract_links(
                            current_url,
                            resp.text,
                            base_domain,
                            depth,
                            links_per_page,
                            visited,
                            recon_data
                        )
                        for link_url in new_links:
                            queue.append((link_url, current_dist + 1))

    # Final update
    update_live_display(
        len(queue),
        len(recon_data["fetched_urls"]),
        len(recon_data["subdomains"]),
        len(recon_data["emails"]),
        len(recon_data["phones"]),
        len(recon_data["socials"]),
        len(recon_data["interesting_pages"]),
        len(recon_data["potential_phones"])
    )

###############################################################################
# Parse Page (Recon + Vuln scanning)
###############################################################################
def parse_page(current_url, resp, base_domain, recon_data, vuln_data, patterns):
    page_text = resp.text
    parsed = urllib.parse.urlparse(current_url)

    # 1) OSINT data
    if is_subdomain(parsed.netloc, base_domain):
        recon_data["subdomains"].add(parsed.netloc)

    for em in EMAIL_REGEX.findall(page_text):
        recon_data["emails"].add(em)

    for ph in PHONE_PLUS_REGEX.findall(page_text):
        recon_data["phones"].add(ph.strip())

    for match in POTENTIAL_PHONE_REGEX.finditer(page_text):
        start_idx, end_idx = match.span()
        phone_text = match.group(1)
        before = page_text[:start_idx].split()
        after = page_text[end_idx:].split()
        before_snippet = " ".join(before[-3:]) if len(before) >= 3 else " ".join(before)
        after_snippet = " ".join(after[:3]) if len(after) >= 3 else " ".join(after)
        snippet = f"... {before_snippet} {phone_text} {after_snippet} ..."
        recon_data["potential_phones"].append((current_url, snippet))

    if any(sd in current_url.lower() for sd in SOCIAL_DOMAINS):
        recon_data["socials"].add(current_url)

    if is_interesting_page(current_url):
        recon_data["interesting_pages"].add(current_url)

    # 2) Vuln scanning
    all_headers = "\n".join([f"{k}: {v}" for k, v in resp.headers.items()])
    combined_text = page_text.lower() + "\n" + all_headers.lower()

    # query_params => if URL param name matches patterns
    q_keys = urllib.parse.parse_qs(parsed.query).keys()
    for param_key in q_keys:
        for pattern in patterns["query_params"]:
            if param_key.lower() == pattern.lower():
                vuln_data["query_params"].append({
                    "url": current_url,
                    "param": param_key
                })

    # now we check other 6 categories in combined_text
    check_for_patterns(patterns["api_wss"], current_url, combined_text, "api_wss", vuln_data)
    check_for_patterns(patterns["common_misconfig"], current_url, combined_text, "common_misconfig", vuln_data)
    check_for_patterns(patterns["injection_points"], current_url, combined_text, "injection_points", vuln_data)
    check_for_patterns(patterns["sensitive_data"], current_url, combined_text, "sensitive_data", vuln_data)
    check_for_patterns(patterns["exposed_files"], current_url, combined_text, "exposed_files", vuln_data)
    check_for_patterns(patterns["js_vulnerabilities"], current_url, combined_text, "js_vulnerabilities", vuln_data)

###############################################################################
# Extract Links
###############################################################################
def extract_links(current_url, page_text, base_domain, spider_depth, spider_links_per_page, visited, recon_data):
    soup = BeautifulSoup(page_text, "html.parser")
    found = []
    count = 0

    for a in soup.find_all('a', href=True):
        new_url = urllib.parse.urljoin(current_url, a['href'])
        if new_url in visited:
            continue

        # Check if it references a known social domain
        if any(sd in new_url.lower() for sd in SOCIAL_DOMAINS):
            recon_data["socials"].add(new_url)

        parsed_new = urllib.parse.urlparse(new_url)
        path_parts = [p for p in parsed_new.path.split('/') if p]
        depth = len(path_parts)

        if parsed_new.netloc.endswith(base_domain):
            if depth <= spider_depth:
                if count < spider_links_per_page:
                    found.append(new_url)
                    count += 1
        else:
            recon_data["external_links"].add(new_url)

    return found

###############################################################################
# Check For Patterns
###############################################################################
def check_for_patterns(pattern_list, current_url, combined_text, category_key, vuln_data):
    for pattern in pattern_list:
        if pattern.lower() in combined_text:
            vuln_data[category_key].append({
                "url": current_url,
                "pattern": pattern
            })

###############################################################################
# Collect Query Parameters
###############################################################################
def collect_parameters(recon_data):
    for url in recon_data["fetched_urls"]:
        parsed = urllib.parse.urlparse(url)
        q_params = urllib.parse.parse_qs(parsed.query)
        for param in q_params.keys():
            recon_data["parameters"].add((url, param))

###############################################################################
# Screenshots
###############################################################################
def take_screenshots(recon_data, config):
    mod_cfg = config.get("modules", {}).get("gowitness", {})
    width = mod_cfg.get("resolution_x", 1440)
    height = mod_cfg.get("resolution_y", 900)
    output_path = mod_cfg.get("output_path", "") or "webshots"

    urls = list(recon_data["fetched_urls"])
    logger.info(f"{CYAN}[SHOTS] Taking screenshots of {len(urls)} pages...{RESET}")

    if not os.path.isdir(output_path):
        os.makedirs(output_path, exist_ok=True)

    max_workers = min(10, len(urls))

    def screenshot_one(url):
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument(f"--window-size={width},{height}")
        service = Service()

        driver = None
        try:
            driver = webdriver.Chrome(service=service, options=chrome_options)
            driver.set_page_load_timeout(8)
            driver.get(url)
            filename = sanitize_filename(url) + ".png"
            path = os.path.join(output_path, filename)
            driver.save_screenshot(path)
            logger.info(f"{GREEN}[SCREENSHOT] {url} => {path}{RESET}")
        except (TimeoutException, WebDriverException) as e:
            logger.error(f"{RED}[SCREENSHOT ERROR] {url}: {e}{RESET}")
        finally:
            if driver:
                driver.quit()

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(screenshot_one, u) for u in urls]
        for _ in concurrent.futures.as_completed(futures):
            pass

def sanitize_filename(url):
    return re.sub(r'[^\w.-]', '_', url)[:200]

###############################################################################
# Save recon_data.json & Vuln.json
###############################################################################
def save_recon_data(recon_data):
    output = {
        "fetched_urls": sorted(recon_data["fetched_urls"]),
        "external_links": sorted(recon_data["external_links"]),
        "subdomains": sorted(recon_data["subdomains"]),
        "emails": sorted(recon_data["emails"]),
        "phones": sorted(recon_data["phones"]),
        "potential_phones": sorted(recon_data["potential_phones"], key=lambda x: x[1]),
        "socials": sorted(recon_data["socials"]),
        "interesting_pages": sorted(recon_data["interesting_pages"]),
        "parameters": sorted(list(recon_data["parameters"]), key=lambda x: x[1])
    }
    with open("recon_data.json", "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

def save_vuln_data(vuln_data):
    with open("Vuln.json", "w", encoding="utf-8") as f:
        json.dump(vuln_data, f, indent=2, ensure_ascii=False)

###############################################################################
# Main
###############################################################################
def main():
    print_banner()
    parser = argparse.ArgumentParser(description="Ghost OSINT + Vuln Crawler (Text-based patterns)")
    parser.add_argument("-u", "--url", required=True, help="Base URL to crawl.")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default=10).")
    parser.add_argument("-ws", action="store_true", help="Take screenshots of fetched pages.")
    parser.add_argument("--wordlists", default="wordlists", help="Directory of .txt pattern files (default=wordlists).")
    args = parser.parse_args()

    # 1) Load config.yaml & BFS constraints
    config = load_config()
    distance, depth, links_per_page = get_spider_constraints(config)

    # 2) Load patterns from .txt files
    patterns = load_patterns(args.wordlists)

    # 3) Prepare data
    recon_data = init_recon_data()
    vuln_data = init_vuln_data()

    # 4) BFS
    try:
        logger.info(f"{CYAN}[START] BFS {args.url} => dist={distance}, depth={depth}, links/page={links_per_page}{RESET}")
        crawl_website(
            args.url,
            distance,
            depth,
            links_per_page,
            args.threads,
            config,
            recon_data,
            vuln_data,
            patterns
        )
    except KeyboardInterrupt:
        logger.warning(f"{RED}[INTERRUPT] User stopped. Saving partial data...{RESET}")

    logger.info(f"{CYAN}[DONE] Fetched {len(recon_data['fetched_urls'])} on-domain URLs.{RESET}")

    # 5) Collect parameters
    collect_parameters(recon_data)

    # 6) Screenshots if -ws
    if args.ws:
        take_screenshots(recon_data, config)

    # 7) Save data
    logger.info(f"{CYAN}[SAVE] Writing recon_data.json & Vuln.json...{RESET}")
    save_recon_data(recon_data)
    save_vuln_data(vuln_data)

    logger.info(f"{GREEN}[COMPLETE] OSINT + Vuln results saved. Exiting.{RESET}")

if __name__ == "__main__":
    main()
