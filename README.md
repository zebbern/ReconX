<div align="center">
    
<img src="https://github.com/user-attachments/assets/b41f4195-fd20-4005-90d6-78598c5a79f8" style="width:45%;">

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Status](https://img.shields.io/badge/Status-Active-green)
![License](https://img.shields.io/badge/License-MIT-brightgreen)


**ReconX is tool for crawling websites to gather OSINT data and identify potential vulnerabilities using customizable text-based patterns. It leverages a breadth-first search (BFS) strategy with multithreading for fast and efficient crawling.**

 [Features](#features)
 [Setup](#setup)
 [Usage](#usage)
 [Showcase](#showcase)
 [Python 3.12+ Pip Fix](#python-312-pip-fix)

---

</div>

## Features

- **OSINT Gathering:** Extracts emails, phone numbers, subdomains, social links, and more.
- **Vulnerability Scanning:** Detects potential vulnerabilities by matching text patterns.
- **Customizable Patterns:** Uses external `.txt` files (in a `wordlists` folder) for scanning.
- **Concurrent Crawling:** Uses multithreading to speed up the crawling process.
- **Optional Screenshots:** Capture page screenshots using Selenium and Chrome WebDriver.

---

## Setup

1. **Clone or Download** `git clone https://github.com/zebbern/ReconX`
2. **Install requirements** `pip install -r requirements.txt` or `pip install requests beautifulsoup4 pyyaml selenium`
3. **Configuration:**
   - (Optional) Change the `config.yaml` in the directory with settings you want or keep them default.
   - (Optional) Adjust crawler settings like user agents, SSL verification, and screenshot options.
4. **Pattern Files:**
   - Ensure the `wordlists` directory contains the following files:
     - `query_params.txt`
     - `api_wss.txt`
     - `common_misconfig.txt`
     - `injection_points.txt`
     - `sensitive_data.txt`
     - `exposed_files.txt`
     - `js_vulnerabilities.txt`
   - customise info in the .txt found in `/wordlists` folder.
  

## Usage

**Run the crawler by providing the base URL:**

    python crawler.py -u https://example.com

### Terminal Options

- `-u`, `--url`  
  **Description:** Base URL to start crawling (required).

- `-t`, `--threads`  
  **Description:** Number of concurrent threads to use (default: 10).

- `-ws`  
  **Description:** Enable screenshot capture for the crawled pages.

**For all options on you can run**

    #Example:
    python crawler.py -u https://example.com -ws -t 10 
    
**Explanation:**
- `-u https://example.com`: Specifies the base URL to crawl.
- `-ws`: Enables screenshots of fetched pages.
- `-t 10`: Uses 10 concurrent threads for faster crawling.
---

### Output

Upon completion, the tool generates two JSON files:

- **recon_data.json:** Contains collected OSINT data (e.g., URLs, emails, subdomains).
- **Vuln.json:** Contains details of detected vulnerabilities based on the pattern matches.

If screenshots are enabled (`-ws`), they will be saved in the directory specified by `config.yaml -> output_path: ""` (default: `webshots`).

---

## Showcase
`Command Used`: python ReconX.py -u https://monolittenil.no | Use `-ws` if you want to include pictures of each site its crawled can also edit `config.yaml` to crawl deeper.

<img width="60%" src="https://github.com/user-attachments/assets/b929cf1c-6d77-443f-b8c6-5c7abdd66168">


<hr>

## Python 3.12+ Pip Fix:
### Create and Activate a Virtual Environment
#### For Linux/macOS:
```
python3 -m venv venv && source venv/bin/activate
```
#### For Windows:
```
python -m venv venv && .\venv\Scripts\activate
```


> [!WARNING]  
> These is intended for educational and ethical hacking purposes only. It should only be used to test systems you own or have explicit permission to test. Unauthorized use of third-party websites or systems without consent is illegal and unethical.
