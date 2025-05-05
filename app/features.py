# for extraction of features
import re
import socket
import whois
import urllib3
import json
import ssl
import requests
from bs4 import BeautifulSoup
from datetime import datetime, timezone
from urllib.parse import urlparse
from urllib.parse import urljoin
from urllib.parse import quote
import pandas as pd


def extract_ip_address(url):
    try:
        domain = urlparse(url).netloc
        # Remove port if present
        domain = domain.split(':')[0]
        # Check for IPv4 or hex IP
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        hex_ip_pattern = re.compile(r'^(0x)?[0-9a-fA-F]{8}$')
        if ip_pattern.match(domain) or hex_ip_pattern.match(domain):
            return -1 
        else:
            return 1  
    except:
        return -1

def extract_long_url(url):
    length = len(url)
    if length < 54:
        return 1  
    elif 54 <= length <= 75:
        return 0 
    else:
        return -1  

def extract_shortening_service(url):
    shortening_services = [
        "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "bit.do", "adf.ly", "buff.ly",
        "is.gd", "cutt.ly", "tiny.cc", "soo.gd", "shorturl.at"
    ]
    parsed = urlparse(url)
    domain = parsed.netloc
    if any(service in domain for service in shortening_services):
        return -1  
    else:
        return 1  

def extract_at_symbol(url):
    if "@" in url:
        return -1  
    else:
        return 1   


def extract_redirecting_double_slash(url):
    """
    Checks if there is an abnormal redirecting '//' in the URL.
    
    Returns:
        -1 : Phishing (last '//' after position 7)
         1 : Legitimate (last '//' at or before position 7)
    """
    last_double_slash = url.rfind("//")
    return -1 if last_double_slash > 7 else 1


def extract_prefix_suffix(url):
    domain = urlparse(url).netloc
    if '-' in domain:
        return -1 
    else:
        return 1   



def extract_subdomains(url):
    domain = urlparse(url).netloc
    if domain.startswith("www."):
        domain = domain[4:]
    dot_count = domain.count('.')
    if dot_count >= 3:
        return -1  
    elif dot_count == 2:
        return 0  
    else:
        return 1  

def extract_https_certificate(url):
    try:
        hostname = url.split("//")[-1].split("/")[0]
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()


        issuer = dict(x[0] for x in cert['issuer'])['organizationName']

        not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')

        cert_age_days = (datetime.utcnow() - not_before).days

        trusted_issuers = [
            'Google Trust Services', 'DigiCert', 'Let\'s Encrypt', 'Cloudflare, Inc.', 'Amazon', 'Sectigo Limited'
        ]

        certificate_info = {
            'issuer': issuer,
            'cert_age_days': cert_age_days
        }

        if issuer in trusted_issuers and cert_age_days >= 365:
            return 1  
        elif issuer in trusted_issuers and cert_age_days < 365:
            return 0 
        else:
            return -1 

    except Exception as e:
        # Handle errors (e.g., no HTTPS, certificate error, or connection error)
        print(f"Error: {e}")
        return -1  
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- SSL certificate expiry function
def get_ssl_cert_expiry(url):
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_before_str = cert['notBefore']
                not_before = datetime.strptime(not_before_str, '%b %d %H:%M:%S %Y %Z')
                not_before = not_before.replace(tzinfo=timezone.utc)
                cert_age_days = (datetime.now(timezone.utc) - not_before).days
                return cert_age_days
    except Exception as e:
        return -1

# --- WHOIS Domain registration length function 
def get_domain_expiry(url):
    try:
        domain = urlparse(url).netloc
        domain = domain.replace("www.", "")
        rdap_url = f"https://rdap.org/domain/{domain}"
        response = requests.get(rdap_url, timeout=5)
        if response.status_code != 200:
            return -1
        
        data = response.json()
        events = data.get("events", [])
        for event in events:
            if event["eventAction"] == "expiration":
                expiry_date = datetime.strptime(event["eventDate"], "%Y-%m-%dT%H:%M:%SZ")
                expiry_date = expiry_date.replace(tzinfo=timezone.utc)
                delta = expiry_date - datetime.now(timezone.utc)
                return 1 if delta.days > 365 else -1
        return -1
    except Exception as e:
        return -1

#  Favicon source check function
def extract_favicon_source(url):
    try:
        response = requests.get(url, timeout=5, verify=False)
        if response.status_code != 200:
            return -1
        
        soup = BeautifulSoup(response.content, 'html.parser')
        link_tag = soup.find("link", rel=lambda x: x and "icon" in x.lower())

        if not link_tag or not link_tag.get("href"):
            return 0  # No favicon

        href = link_tag['href']
        favicon_url = urljoin(url, href)
        
        parsed_favicon = urlparse(favicon_url)
        parsed_url = urlparse(url)

        if parsed_favicon.netloc == parsed_url.netloc or parsed_favicon.netloc == "":
            return 1  # Internal favicon
        else:
            return -1  # External favicon
    except Exception as e:
        return -1


# Feature 11: Non-Standard Port
def has_non_standard_port(url):
    try:
        parsed = urlparse(url)

        if parsed.port:
            port = parsed.port
        elif parsed.scheme == 'http':
            port = 80
        elif parsed.scheme == 'https':
            port = 443
        else:
            port = -1  

        if port in [80, 443]:
            return 1 
        else:
            return -1 
    except Exception as e:
        print(f"Error checking port for {url}: {e}")
        return -1  # Assume phishing if error


# Feature 12: HTTPS Token in Domain
def has_https_token_in_domain(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if "https" in domain.replace("https://", "").replace("http://", ""):
            return -1 
        else:
            return 1  
    except Exception as e:
        print(f"Error checking HTTPS token in domain for {url}: {e}")
        return -1 



def request_url_feature(url):
    try:
        domain = urlparse(url).netloc
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, 'html.parser')

        total_resources = 0
        same_domain_resources = 0

        tags = soup.find_all(['img', 'script', 'link'])
        for tag in tags:
            src = tag.get('src') or tag.get('href')
            if src:
                total_resources += 1
                src_url = urljoin(url, src)
                src_domain = urlparse(src_url).netloc
                if domain in src_domain:
                    same_domain_resources += 1

        if total_resources == 0:
            return 0

        percentage = (same_domain_resources / total_resources) * 100

        if percentage >= 61:
            return 1  
        elif 22 <= percentage < 61:
            return 0 
        else:
            return -1  
    except:
        return 0  

def url_of_anchor_feature(url):
    try:
        domain = urlparse(url).netloc
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, 'html.parser')

        total_anchors = 0
        same_domain_anchors = 0

        anchors = soup.find_all('a')
        for anchor in anchors:
            href = anchor.get('href')
            if href:
                total_anchors += 1
                href_url = urljoin(url, href)
                href_domain = urlparse(href_url).netloc
                if domain in href_domain:
                    same_domain_anchors += 1

        if total_anchors == 0:
            return 0  

        percentage = (same_domain_anchors / total_anchors) * 100

        if percentage >= 67:
            return 1 
        elif 31 <= percentage < 67:
            return 0  
        else:
            return -1 
    except:
        return 0  

def links_in_tags_feature(url):
    try:
        domain = urlparse(url).netloc
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, 'html.parser')

        total_links = 0
        same_domain_links = 0

        tags = soup.find_all(['meta', 'script', 'link'])
        for tag in tags:
            src = tag.get('content') or tag.get('src') or tag.get('href')
            if src:
                total_links += 1
                src_url = urljoin(url, src)
                src_domain = urlparse(src_url).netloc
                if domain in src_domain:
                    same_domain_links += 1

        if total_links == 0:
            return 0  

        percentage = (same_domain_links / total_links) * 100

        if percentage >= 81:
            return 1 
        elif 17 <= percentage < 81:
            return 0 
        else:
            return -1  
    except:
        return 0 


def sfh_feature(url):
    try:
        domain = urlparse(url).netloc
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, 'html.parser')

        forms = soup.find_all('form')
        if not forms:
            return 1 

        for form in forms:
            action = form.get('action')
            if not action or action.strip() == "about:blank":
                return -1 

            action_url = urljoin(url, action)
            action_domain = urlparse(action_url).netloc

            if domain not in action_domain:
                return 0 

        return 1 
    except:
        return 0 

def extract_submitting_to_email(url):
    try:
        if 'mailto:' in url.lower() or 'mail(' in url.lower():
            return -1
        
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')

        for tag in soup.find_all(['form', 'a'], href=True):
            href = tag.get('href', '').lower()
            if 'mailto:' in href or 'mail(' in href:
                return -1

        for script in soup.find_all('script'):
            if script.string and ('mailto:' in script.string.lower() or 'mail(' in script.string.lower()):
                return -1

        return 1  
    except Exception as e:
        print("Error:", e)
        return -1


def abnormal_url(url):
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc.lower().replace("www.", "")
        full_url = url.lower()

        ip_pattern = r'^\d{1,3}(\.\d{1,3}){3}$'
        if re.match(ip_pattern, hostname):
            return -1

        return 1 if hostname in full_url else -1
    except:
        return -1 


def check_website_forwarding(url):
    try:
        response = requests.get(url, allow_redirects=True, timeout=5)
        redirects = len(response.history)
        if redirects == 0 or redirects == 1:
            return 1
        elif redirects >= 4:
            return -1
        else:
            return 0
    except:
        return 0


def extract_status_bar_customization(url):
    try:
        response = requests.get(url, timeout=10)
        page_source = response.text

        if 'onMouseOver' in page_source and ('window.status' in page_source or 'status=' in page_source):
            return -1  
        else:
            return 1   

    except Exception as e:
        print("Error fetching page source:", e)
        return -1 


def extract_disable_right_click(url):
    try:
        response = requests.get(url, timeout=10)
        page_source = response.text.replace(" ", "").lower()

        if 'event.button==2' in page_source or 'oncontextmenu="returnfalse"' in page_source:
            return -1  
        else:
            return 1  
    except Exception as e:
        print("Error checking right-click disable:", e)
        return -1


def extract_popup_window(url):
    try:
        response = requests.get(url, timeout=10)
        page_source = response.text.lower()

        if 'window.open' in page_source:
            return -1 
        else:
            return 1 
    except Exception as e:
        print("Error checking popup window:", e)
        return -1  

def iframe_redirection_feature(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, 'html.parser')

        if soup.find_all(['iframe', 'frame']):
            return -1 
        else:
            return 1  

    except Exception as e:
        print(f"[Error - iFrame] Failed to fetch page: {e}")
        return -1 

def check_age_of_domain(url):
    try:
        domain = urlparse(url).netloc
        domain_info = whois.whois(domain)

        if domain_info.creation_date is None:
            return -1 

        if isinstance(domain_info.creation_date, list):
            creation_date = domain_info.creation_date[0]
        else:
            creation_date = domain_info.creation_date

        current_date = datetime.datetime.now()
        age_in_months = (current_date.year - creation_date.year) * 12 + (current_date.month - creation_date.month)

        if age_in_months >= 6:
            return 1 
        else:
            return -1 
    except:
        return -1  


def check_dns_record(url):
    try:
        domain = urlparse(url).netloc
        domain_info = whois.whois(domain)

        if domain_info.domain_name:
            return 1 
        else:
            return -1 
    except:
        return -1 


def check_website_traffic(url):
    # Load the Tranco dataset.(Can be done with other methods but that require paid api)
    c = pd.read_csv('tranco_top1m.csv', header=None)  # Assuming no header in the CSV file

    domain = urlparse(url).netloc.lower()

    if domain.startswith("www."):
        domain = domain[4:]

    if domain in c[1].values: 

        rank = c[c[1] == domain].index[0] + 1 
        
        if rank < 100000:
            return 1  
        else:
            return 0  
    else:
        return -1 

def check_number_of_links(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')

        domain = urlparse(url).netloc
        external_links = set()

        for link in soup.find_all('a', href=True):
            href = link['href']
            parsed_href = urlparse(href)
            if parsed_href.netloc and parsed_href.netloc != domain:
                external_links.add(parsed_href.netloc)

        count = len(external_links)

        if count == 0:
            return -1  
        elif count == 1:
            return 0   
        else:
            return 1   
    except:
        return 0 



#  Replace with your actual API key (keep it secret in production)
GOOGLE_API_KEY = "YOUR_GOOGLE_API_KEY"  # Example: "AIzaSyAxxxx..."

def check_statistical_reports(url):
    try:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"

        payload = {
            "client": {
                "clientId": "yourcompanyname",       # Any string
                "clientVersion": "1.0"               # Any version string
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": url}
                ]
            }
        }

        headers = {'Content-Type': 'application/json'}

        response = requests.post(endpoint, headers=headers, data=json.dumps(payload), timeout=10)

        if response.status_code != 200:
            print(f"[Error] Google API returned status code: {response.status_code}")
            return 0  # Suspicious if we can’t verify

        result = response.json()

        if "matches" in result:
            return -1  #  Phishing or malicious
        else:
            return 1   # Safe
    except Exception as e:
        print(f"[Exception - Statistical Report] {e}")
        return 0  # Suspicious on error


def extract_features(url):
    return [
        extract_ip_address(url),
        extract_long_url(url),
        extract_shortening_service(url),
        extract_at_symbol(url),
        extract_redirecting_double_slash(url),
        extract_prefix_suffix(url),
        extract_subdomains(url),
        extract_https_certificate(url),
        get_domain_expiry(url),
        extract_favicon_source(url),
        has_non_standard_port(url),
        has_https_token_in_domain(url),
        request_url_feature(url),
        url_of_anchor_feature(url),
        links_in_tags_feature(url),
        sfh_feature(url),
        extract_submitting_to_email(url),
        abnormal_url(url),
        check_website_forwarding(url),
        extract_status_bar_customization(url),
        extract_disable_right_click(url),
        extract_popup_window(url),
        iframe_redirection_feature(url),
        check_age_of_domain(url),
        check_dns_record(url),
        check_website_traffic(url),
        check_number_of_links(url),
        check_statistical_reports(url)
    ]