import os
import sys
import re
import json
import requests
import textwrap
import socket
from lxml.html import fromstring
from getpass import getpass
from shutil import which
from threading import Thread
from time import sleep
from bs4 import BeautifulSoup
from tabulate import tabulate
import pyperclip
import requests
import random
import string
import time
import sys
import re
import os
import stat

# ==================== SECURITY FUNCTIONS ====================

def sanitize_input(user_input, allowed_chars=None, max_length=500):
    """Sanitize user input to prevent injection attacks."""
    if not user_input:
        return ""
    # Remove null bytes and control characters
    sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', str(user_input))
    # Limit length
    sanitized = sanitized[:max_length]
    # If specific allowed chars defined, filter to those
    if allowed_chars:
        sanitized = ''.join(c for c in sanitized if c in allowed_chars)
    return sanitized.strip()

def sanitize_username(username):
    """Sanitize username - only alphanumeric, underscore, dot, hyphen."""
    allowed = string.ascii_letters + string.digits + '_.-'
    return sanitize_input(username, allowed_chars=allowed, max_length=100)

def sanitize_domain(domain):
    """Sanitize domain/IP input."""
    allowed = string.ascii_letters + string.digits + '.-:'
    return sanitize_input(domain, allowed_chars=allowed, max_length=255)

def sanitize_phone(phone):
    """Sanitize phone number - only digits and +."""
    allowed = string.digits + '+'
    return sanitize_input(phone, allowed_chars=allowed, max_length=20)

def sanitize_email(email):
    """Sanitize email input."""
    allowed = string.ascii_letters + string.digits + '@._+-'
    return sanitize_input(email, allowed_chars=allowed, max_length=254)

def set_secure_permissions(filepath):
    """Set file permissions to owner-only (600)."""
    try:
        os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass

def secure_write_file(filepath, content):
    """Write file with secure permissions."""
    with open(filepath, 'w') as f:
        f.write(content)
    set_secure_permissions(filepath)

def print_security_warning(message):
    """Print a security warning."""
    print(f"\033[33m[SECURITY WARNING]\033[0m {message}")

# ==================== PHONE LOOKUP ENHANCEMENTS ====================

# German carrier database (offline lookup by prefix)
GERMAN_CARRIERS = {
    # T-Mobile / Telekom
    '0151': 'T-Mobile (Telekom)', '0160': 'T-Mobile (Telekom)', '0170': 'T-Mobile (Telekom)',
    '0171': 'T-Mobile (Telekom)', '0175': 'T-Mobile (Telekom)',
    # Vodafone
    '0152': 'Vodafone', '0162': 'Vodafone', '0172': 'Vodafone', '0173': 'Vodafone', '0174': 'Vodafone',
    # O2 / Telefónica
    '0157': 'O2 (Telefónica)', '0159': 'O2 (Telefónica)', '0163': 'O2 (Telefónica)',
    '0176': 'O2 (Telefónica)', '0177': 'O2 (Telefónica)', '0178': 'O2 (Telefónica)', '0179': 'O2 (Telefónica)',
    # E-Plus (now O2)
    '0155': 'O2 (ehem. E-Plus)', '0156': 'O2 (ehem. E-Plus)', '0164': 'O2 (ehem. E-Plus)',
    # Drillisch / 1&1
    '0153': '1&1 Drillisch', '0161': '1&1 Drillisch', '0165': '1&1 Drillisch', '0166': '1&1 Drillisch', '0167': '1&1 Drillisch',
}

# Country codes for auto-detection
COUNTRY_PREFIXES = {
    '0049': '+49', '49': '+49',  # Germany
    '0043': '+43', '43': '+43',  # Austria
    '0041': '+41', '41': '+41',  # Switzerland
    '0044': '+44', '44': '+44',  # UK
    '001': '+1', '1': '+1',      # USA/Canada
    '0033': '+33', '33': '+33',  # France
    '0031': '+31', '31': '+31',  # Netherlands
}

def normalize_phone_number(phone, default_country='+49'):
    """Normalize phone number to international format."""
    phone = phone.strip().replace(' ', '').replace('-', '').replace('/', '')

    # Already international format
    if phone.startswith('+'):
        return phone

    # German format starting with 0
    if phone.startswith('00'):
        # International format with 00 prefix
        for prefix, intl in COUNTRY_PREFIXES.items():
            if phone.startswith(prefix):
                return intl + phone[len(prefix):]
        return '+' + phone[2:]

    # Local format (e.g., 0160...)
    if phone.startswith('0'):
        return default_country + phone[1:]

    return default_country + phone

def get_carrier_offline(phone):
    """Get carrier from offline database (German numbers only)."""
    # Normalize to local format for prefix matching
    if phone.startswith('+49'):
        local = '0' + phone[3:]
    elif phone.startswith('0049'):
        local = '0' + phone[4:]
    else:
        local = phone

    # Check prefixes
    for prefix, carrier in GERMAN_CARRIERS.items():
        if local.startswith(prefix):
            return carrier
    return None

def get_phone_type_offline(phone):
    """Determine if mobile or landline (German numbers)."""
    normalized = normalize_phone_number(phone)
    if normalized.startswith('+49'):
        local = '0' + normalized[3:]
        # German mobile prefixes start with 015, 016, 017
        if local[:3] in ['015', '016', '017']:
            return 'mobile'
        # Landline prefixes
        if local[:2] in ['02', '03', '04', '05', '06', '07', '08', '09']:
            return 'landline'
    return 'unknown'

def check_spam_reputation(phone):
    """Check phone number spam reputation using free APIs."""
    results = []
    normalized = normalize_phone_number(phone)

    # Check with tellows (scraping - no API key needed)
    try:
        tellows_url = f"https://www.tellows.de/num/{normalized.replace('+', '00')}"
        # Note: In production, you'd scrape this. For now, return placeholder
        results.append({'source': 'tellows', 'url': tellows_url, 'status': 'check_manually'})
    except:
        pass

    # Check with CleverDialer
    try:
        cleverdialer_url = f"https://www.cleverdialer.de/telefonnummer/{normalized.replace('+49', '0')}"
        results.append({'source': 'cleverdialer', 'url': cleverdialer_url, 'status': 'check_manually'})
    except:
        pass

    return results

def search_phone_social_media(phone):
    """Generate social media search URLs for phone number."""
    normalized = normalize_phone_number(phone)
    local = normalized.replace('+49', '0') if normalized.startswith('+49') else normalized

    searches = [
        {'platform': 'Google', 'url': f'https://www.google.com/search?q="{normalized}"'},
        {'platform': 'Google (local)', 'url': f'https://www.google.com/search?q="{local}"'},
        {'platform': 'Facebook', 'url': f'https://www.facebook.com/search/top?q={normalized}'},
        {'platform': 'LinkedIn', 'url': f'https://www.linkedin.com/search/results/all/?keywords={normalized}'},
        {'platform': 'Sync.me', 'url': f'https://sync.me/search/?number={normalized}'},
        {'platform': 'Truecaller', 'url': f'https://www.truecaller.com/search/de/{local}'},
    ]
    return searches

# ==================== END PHONE LOOKUP ENHANCEMENTS ====================

# ==================== IMAGE/METADATA FUNCTIONS ====================

def extract_image_metadata(filepath):
    """Extract EXIF and metadata from image files."""
    metadata = {}

    try:
        from PIL import Image
        from PIL.ExifTags import TAGS, GPSTAGS

        img = Image.open(filepath)
        metadata['format'] = img.format
        metadata['mode'] = img.mode
        metadata['size'] = f"{img.width}x{img.height}"

        # Extract EXIF data
        exif_data = img._getexif()
        if exif_data:
            for tag_id, value in exif_data.items():
                tag = TAGS.get(tag_id, tag_id)

                # Handle GPS data specially
                if tag == "GPSInfo":
                    gps_data = {}
                    for gps_tag_id, gps_value in value.items():
                        gps_tag = GPSTAGS.get(gps_tag_id, gps_tag_id)
                        gps_data[gps_tag] = gps_value
                    metadata['GPSInfo'] = gps_data
                elif isinstance(value, bytes):
                    try:
                        metadata[tag] = value.decode('utf-8', errors='ignore')
                    except:
                        metadata[tag] = str(value)[:100]
                else:
                    metadata[tag] = str(value)[:200] if len(str(value)) > 200 else value

        img.close()
    except ImportError:
        metadata['error'] = "PIL/Pillow not installed. Run: pip install Pillow"
    except Exception as e:
        metadata['error'] = str(e)

    return metadata

def extract_gps_coordinates(gps_info):
    """Convert GPS EXIF data to decimal coordinates."""
    try:
        def convert_to_degrees(value):
            d = float(value[0])
            m = float(value[1])
            s = float(value[2])
            return d + (m / 60.0) + (s / 3600.0)

        lat = convert_to_degrees(gps_info.get('GPSLatitude', [0,0,0]))
        lat_ref = gps_info.get('GPSLatitudeRef', 'N')
        if lat_ref == 'S':
            lat = -lat

        lon = convert_to_degrees(gps_info.get('GPSLongitude', [0,0,0]))
        lon_ref = gps_info.get('GPSLongitudeRef', 'E')
        if lon_ref == 'W':
            lon = -lon

        return lat, lon
    except:
        return None, None

def extract_pdf_metadata(filepath):
    """Extract metadata from PDF files."""
    metadata = {}

    try:
        import subprocess
        # Try using pdfinfo if available
        result = subprocess.run(['pdfinfo', filepath], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    metadata[key.strip()] = value.strip()
    except:
        pass

    # Fallback: Try reading PDF header
    try:
        with open(filepath, 'rb') as f:
            content = f.read(2048).decode('utf-8', errors='ignore')

            # Extract common PDF metadata patterns
            patterns = {
                'Author': r'/Author\s*\(([^)]+)\)',
                'Creator': r'/Creator\s*\(([^)]+)\)',
                'Producer': r'/Producer\s*\(([^)]+)\)',
                'Title': r'/Title\s*\(([^)]+)\)',
                'CreationDate': r'/CreationDate\s*\(([^)]+)\)',
                'ModDate': r'/ModDate\s*\(([^)]+)\)',
            }

            for key, pattern in patterns.items():
                match = re.search(pattern, content)
                if match:
                    metadata[key] = match.group(1)
    except Exception as e:
        metadata['error'] = str(e)

    return metadata

def generate_reverse_image_urls(image_path_or_url):
    """Generate URLs for reverse image search services."""

    # If it's a URL, use it directly; otherwise, note that file upload is needed
    is_url = image_path_or_url.startswith('http')

    services = []

    if is_url:
        encoded_url = requests.utils.quote(image_path_or_url, safe='')
        services = [
            {'name': 'Google Images', 'url': f'https://lens.google.com/uploadbyurl?url={encoded_url}', 'type': 'direct'},
            {'name': 'Yandex', 'url': f'https://yandex.com/images/search?url={encoded_url}&rpt=imageview', 'type': 'direct'},
            {'name': 'Bing Visual', 'url': f'https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:{encoded_url}', 'type': 'direct'},
            {'name': 'TinEye', 'url': f'https://tineye.com/search?url={encoded_url}', 'type': 'direct'},
        ]
    else:
        services = [
            {'name': 'Google Images', 'url': 'https://images.google.com/ (upload image)', 'type': 'upload'},
            {'name': 'Yandex', 'url': 'https://yandex.com/images/ (upload image)', 'type': 'upload'},
            {'name': 'TinEye', 'url': 'https://tineye.com/ (upload image)', 'type': 'upload'},
            {'name': 'Bing Visual', 'url': 'https://www.bing.com/visualsearch (upload image)', 'type': 'upload'},
        ]

    # Face-specific search services (always manual upload)
    face_services = [
        {'name': 'PimEyes', 'url': 'https://pimeyes.com/', 'note': 'Face recognition search'},
        {'name': 'FaceCheck.ID', 'url': 'https://facecheck.id/', 'note': 'Face search engine'},
        {'name': 'Search4faces', 'url': 'https://search4faces.com/', 'note': 'VK/OK face search'},
    ]

    return services, face_services

# ==================== END IMAGE/METADATA FUNCTIONS ====================

r = "\033[31m"
g = "\033[32m"
y = "\033[33m"
b = "\033[34m"
p = "\033[35m"
d = "\033[2;37m"
w = "\033[0m"
lr = "\u001b[38;5;196m"

W = f"{w}\033[1;47m"
R = f"{w}\033[1;41m"
G = f"{w}\033[1;42m"
Y = f"{w}\033[1;43m"
B = f"{w}\033[1;44m"


mail_printate = []
configs = json.loads(open("configs/config.json", "r").read())
home = os.getenv("HOME")
cookifile = f"{home}/.cookies"
space = "         "
lines =  space + "-"*44
apihack = "https://api.hackertarget.com/{}/?q={}"
mbasic = "https://mbasic.facebook.com{}"
graph = "https://graph.facebook.com{}"
userrecon_num = 0
userrecon_working = 0
userrecon_results = []
check_email_num = 0
headers = {"User-Agent":"Opera/9.80 (J2ME/MIDP; Opera Mini/9.80 (S60; SymbOS; Opera Mobi/23.334; U; id) Presto/2.5.25 Version/10.54"}
logo = f"""{b}
      .---.        .-----------
     /     \  __  /    ------
    / /     \(  )/    -----           
   //////   ' \/ `   ---            ┏───────────────────────────────┓
  //// / // :    : ---              │     WELCOME TO EAGLEOSINT     │
 // /   /  /`    '--                │     discord.gg/wQqZpHX2V2     │
//          //..\\                   │     github.com/retr0-g04t     │
       ====UU====UU====             └───────────────────────────────┘
           '//||\\`
             ''``
  {d}Simple Information Gathering Toolkit{w}    
  {d}Authors: {w}{r}@Retr0{d} & {w}{r}💳 | NDL{w}
"""

def menu():
    os.system("clear")
    print(logo)
    print(f"""
         {W}\033[2;30m Choose number or type exit for exiting {w}
    
        {w}{b}  01{w} Userrecon     {d} Username reconnaissance 
        {w}{b}  02{w} Facedumper    {d} Dump facebook information
        {w}{b}  03{w} Mailfinder    {d} Find email with name
        {w}{b}  04{w} Godorker      {d} Dorking with google search
        {w}{b}  05{w} Phoneinfo     {d} Phone number information
        {w}{b}  06{w} DNSLookup     {d} Domain name system lookup
        {w}{b}  07{w} Whoislookup   {d} Identify who is on domain
        {w}{b}  08{w} Sublookup     {d} Subnetwork lookup
        {w}{b}  09{w} Hostfinder    {d} Find host domain
        {w}{b}  10{w} DNSfinder     {d} Find host domain name system
        {w}{b}  11{w} RIPlookup     {d} Reverse IP lookup
        {w}{b}  12{w} IPlocation    {d} IP to location tracker
        {w}{b}  13{w} Bitly Bypass  {d} Bypass all bitly urls
        {w}{b}  14{w} Github Lookup {d} Dump GitHub information
        {w}{b}  15{w} TempMail {d}      Generate Temp Mail and Mail Box
        {w}{b}  16{w} Metadata      {d} Extract metadata from images/PDFs
        {w}{b}  17{w} FaceSearch    {d} Reverse image & face search
        {w}{b}  00{w} Exit          {d} bye bye ):
        """)
    mainmenu()

def mainmenu():
    while True: 
        try:
            cmd = input(f"{space}{w}{b}>{w} choose:{b} ")
            if int(len(cmd)) < 6:
                if cmd in ("exit","Exit", "00", "0"): exit(r+space+"* Exiting !"+w)
                elif cmd in ("1","01"): userrecon()
                elif cmd in ("2","02"): fb.facedumper()
                elif cmd in ("3","03"): mailfinder()
                elif cmd in ("4","04"): godorker()
                elif cmd in ("5","05"): phoneinfo()
                elif cmd in ("6","06"): infoga("dnslookup")
                elif cmd in ("7","07"): infoga("whois")
                elif cmd in ("8","08"): infoga("subnetcalc")
                elif cmd in ("9","09"): infoga("hostsearch")
                elif cmd in ("10"): infoga("mtr")
                elif cmd in ("11"): infoga("reverseiplookup")
                elif cmd in ("12"): iplocation()
                elif cmd in ("14"): github_lookup()
                elif cmd in ("13"): bypass_bitly()
                elif cmd in ("15"): temp_mail_gen()
                elif cmd in ("16"): metadata_extractor()
                elif cmd in ("17"): face_search()
            else: continue
        except KeyboardInterrupt:
            exit(f"{r}\n{space}* Aborted !")

def display_progress(iteration, total, text=""):
    bar_max_width = 40
    bar_current_width = bar_max_width * iteration // total
    bar = "█" * bar_current_width + " " * (bar_max_width - bar_current_width)
    progress = "%.1f" % (iteration / total * 100)
    print(f"{space}{iteration}/{total} |{bar}| {progress}% {text}", end="\r")
    if iteration == total:
        print()

def send_req(url, username):
    try:
        req = requests.get(url.format(username), headers=headers)
    except requests.exceptions.Timeout: pass
    except requests.exceptions.TooManyRedirects: pass
    except requests.exceptions.ConnectionError: pass
    global userrecon_num, userrecon_results, userrecon_working
    userrecon_num += 1
    

    if req.status_code == 200: color = g; userrecon_working += 1
    elif req.status_code == 404: color = r
    else: color = y

    percent = 71/100*userrecon_num
    display_progress(userrecon_num, 71, f"FOUND: {userrecon_working}")

    userrecon_results.append(f"  {space}{b}[{color}{req.status_code}{b}] {userrecon_num}/71 {w}{url.format(username)}")

def check_email(email, api, total, ok, f):

    response = requests.get("https://isitarealemail.com/api/email/validate",params = {'email': email}, headers = {'Authorization': "Bearer " + api })
    status = response.json()['status']
    
    if status == 'invalid': color = r; back_color = R
    elif status == 'unknown': color = y; back_color = Y
    else: color = g; back_color = G
    

    global check_email_num
    check_email_num += 1
    if status == "valid":
        ok.append(email)
        f.write(email+"\n")
        print_space = "  "
    else:
        print_space = " "

    #if check_email_num < 0:

    print(f"{space}{back_color}{w}{print_space}{status.upper()}{print_space}{w}{b} {check_email_num}/{total}{w} Status: {color}{status}{w} Email: {email}")
    

def iplocation():
    # SECURITY: Ask before revealing local IP
    show_local = input(f"{space}{b}>{w} Show your local IP? (y/N):{b} ").lower().strip()
    if show_local == 'y':
        print_security_warning("Fetching your public IP address...")
        print(f"{space}{b}>{w} local IP: {os.popen('curl ifconfig.co --silent').readline().strip()}")
    x = sanitize_domain(input(f"{space}{b}>{w} enter IP:{b} "))
    if not x or not x.split(".")[0].isnumeric():
        menu()
        return
    print(w+lines)
    req = requests.get("https://ipinfo.io/"+x+"/json").json()
    try: ip = "IP: "+req["ip"]
    except KeyError: ip = ""
    try: city = "CITY: "+req["city"]
    except KeyError: city = ""
    try: country = "COUNTRY: "+req["country"]
    except KeyError: country = ""
    try: loc = "LOC: "+req["loc"]
    except KeyError: loc = ""
    try: org = "ORG: "+req["org"]
    except KeyError: org = ""
    try: tz = "TIMEZONE: "+req["timezone"]
    except KeyError: tz = ""
    z = [ip, city, country, loc, org, tz]
    for res in z:
        print(f"{space}{b}-{w} {res}")
    print(w+lines)
    getpass(space+"press enter for back to previous menu ")
    menu()

def infoga(opt):
    x = sanitize_domain(input(f"{space}{b}>{w} enter domain or IP:{b} "))
    if not x: menu()
    try:
        if x.split(".")[0].isnumeric(): x = socket.gethostbyname(x)
    except socket.gaierror:
        print(f"{space}{r}>{w} Invalid domain or IP")
        menu()
    print(w+lines)
    req = requests.get(apihack.format(opt,x),stream=True)
    for res in req.iter_lines():
        print(f"{space}{b}-{w} {res.decode('utf-8')}")
    print(w+lines)
    getpass(space+"press enter for back to previous menu ")
    menu()

def phoneinfo():
    no = sanitize_phone(input(f"{space}{b}>{w} enter number:{b} "))
    if not no:
        menu()
        return

    # Normalize phone number (auto-add country code)
    normalized = normalize_phone_number(no)
    local_format = normalized.replace('+49', '0') if normalized.startswith('+49') else no

    print(w+lines)
    print(f"{space}{B}  PHONE ANALYSIS  {w}")
    print(w+lines)

    # ===== SECTION 1: Basic Info (Offline) =====
    print(f"\n{space}{p}[ BASIC INFO (Offline) ]{w}")
    print(f"{space}{b}-{w} Input               :    {y}{no}{w}")
    print(f"{space}{b}-{w} International       :    {y}{normalized}{w}")
    print(f"{space}{b}-{w} Local Format        :    {y}{local_format}{w}")

    # Offline carrier detection
    carrier_offline = get_carrier_offline(no)
    if carrier_offline:
        print(f"{space}{b}-{w} Carrier (offline)   :    {g}{carrier_offline}{w}")

    # Phone type detection
    phone_type = get_phone_type_offline(no)
    print(f"{space}{b}-{w} Type                :    {y}{phone_type}{w}")

    # ===== SECTION 2: API Lookup (Veriphone) =====
    print(f"\n{space}{p}[ API LOOKUP (Veriphone) ]{w}")
    api_key = configs.get('veriphone-api-key', '')
    if api_key == "":
        print_security_warning("API key will be stored in plaintext in configs/config.json")
        api_key = input(f"{space}{w}{b}>{w} enter your api key (https://veriphone.io) :{b} ")
        if api_key:
            configs["veriphone-api-key"] = api_key
            secure_write_file("configs/config.json", json.dumps(configs, indent=2))

    if api_key:
        try:
            url = "https://api.veriphone.io/v2/verify?phone={}&key=" + api_key
            req = requests.get(url.format(normalized), timeout=10)
            res = json.loads(req.text)
            for info in res:
                print(f"{space}{b}-{w} {info}{' '*(20-len(str(info)))}:    {y}{res[info]}{w}")
        except requests.exceptions.RequestException as e:
            print(f"{space}{r}-{w} API Error: {e}")
        except json.JSONDecodeError:
            print(f"{space}{r}-{w} Invalid API response")
    else:
        print(f"{space}{d}  (skipped - no API key){w}")

    # ===== SECTION 3: NumVerify API (optional) =====
    print(f"\n{space}{p}[ API LOOKUP (NumVerify) ]{w}")
    numverify_key = configs.get('numverify-api-key', '')
    if numverify_key:
        try:
            nv_url = f"http://apilayer.net/api/validate?access_key={numverify_key}&number={normalized}"
            nv_req = requests.get(nv_url, timeout=10)
            nv_res = json.loads(nv_req.text)
            for info in nv_res:
                if info not in ['valid', 'number']:  # Skip duplicates
                    print(f"{space}{b}-{w} {info}{' '*(20-len(str(info)))}:    {y}{nv_res[info]}{w}")
        except:
            print(f"{space}{r}-{w} NumVerify API Error")
    else:
        print(f"{space}{d}  (skipped - no API key, get free key at numverify.com){w}")

    # ===== SECTION 4: Spam/Reputation Check =====
    print(f"\n{space}{p}[ SPAM/REPUTATION CHECK ]{w}")
    spam_results = check_spam_reputation(no)
    for result in spam_results:
        print(f"{space}{b}-{w} {result['source']}: {d}{result['url']}{w}")

    # ===== SECTION 5: Social Media Search =====
    print(f"\n{space}{p}[ SOCIAL MEDIA SEARCH ]{w}")
    social_results = search_phone_social_media(no)
    for result in social_results:
        print(f"{space}{b}-{w} {result['platform']}: {d}{result['url']}{w}")

    # ===== SECTION 6: Copy to Clipboard =====
    try:
        pyperclip.copy(normalized)
        print(f"\n{space}{g}✓{w} International number copied to clipboard")
    except:
        pass

    print(w+lines)
    print(f"{space}{B} DONE {R} {normalized} {w}")

    getpass(space+"press enter for back to previous menu ")
    menu()

def godorker():
    dork = sanitize_input(input(f"{space}{b}>{w} enter dork (inurl/intext/etc):{b} "), max_length=200).lower()
    if not dork: menu()
    print(w+lines)
    urls = []
    s = search(dork,num_results=30)
    for line in s:
        urls.append(line)
    f = open("result_godorker.txt","w")
    f.write("# Dork: "+dork+"\n\n")
    for url in urls:
        try:
            req = requests.get(url,headers=headers)
            res = fromstring(req.content)
            string = res.findtext(".//title")
            wrapper = textwrap.TextWrapper(width=47)
            dedented_text = textwrap.dedent(text=string)
            original = wrapper.fill(text=dedented_text)
            shortened = textwrap.shorten(text=original, width=47)
            title = wrapper.fill(text=shortened)
            f.write(url+"\n")
            print(f"{space}{B} FOUND {w} {str(title)}\n{space}{d}{url}{w}")
        except TypeError: pass
        except requests.exceptions.InvalidSchema: break
        except requests.exceptions.ConnectionError: break
        except KeyboardInterrupt: break
    f.close()
    print(w+lines)
    print(f"{space}{b}>{w} {str(len(url))} retrieved as: {y}result_godorker.txt{w}")
    getpass(space+"press enter for back to previous menu ")
    menu()

def mailfinder():
    # Allow letters, spaces, and common name characters
    allowed_name_chars = string.ascii_letters + ' ' + '-\''
    fullname = sanitize_input(input(f"{space}{b}>{w} enter name:{b} "), allowed_chars=allowed_name_chars, max_length=100).lower()
    if not fullname: menu()
    data = [
        "gmail.com",
        "yahoo.com",
        "hotmail.com",
        "aol.com",
        "msn.com",
        "comcast.net",
        "live.com",
        "rediffmail.com",
        "ymail.com",
        "outlook.com",
        "cox.net",
        "googlemail.com",
        "rocketmail.com",
        "att.net",
        "facebook.com",
        "bellsouth.net",
        "charter.net",
        "sky.com",
        "earthlink.net",
        "optonline.net",
        "qq.com",
        "me.com",
        "gmx.net",
        "mail.com",
        "ntlworld.com",
        "frontiernet.net",
        "windstream.net",
        "mac.com",
        "centurytel.net",
        "aim.com",
        ]
    listuser = [
        fullname.replace(" ",""),
        fullname.replace(" ","")+"123",
        fullname.replace(" ","")+"1234",
        fullname.replace("i", "1"),
        fullname.replace("a", "4"),
        fullname.replace("e", "3"),
        fullname.replace("i", "1").replace("a", "4").replace("e", "3"),
        fullname.replace("i", "1").replace("a", "4"),
        fullname.replace("i", "1").replace("e", "3"),
        fullname.replace("a", "4").replace("e", "3"),
        ]
    
    names = []
    for name in fullname.split(" "):
        listuser.append(name)
        listuser.append(name+"123")
        listuser.append(name+"1234")
        names.append(name)
    
    f = open("result_mailfinder.txt","w")
    ok = []
    results = []
    try:
        api = configs["real-email-api-key"]
        if api == "":
            print_security_warning("API key will be stored in plaintext in configs/config.json")
            api = input(f"{space}{w}{b}>{w} enter your api key (https://isitarealemail.com) :{b} ")
            configs["real-email-api-key"] = api
            secure_write_file("configs/config.json", json.dumps(configs, indent=2))
        print(w+lines)
        for user in listuser:
            for domain in data:
                email = user + "@" + domain
                

                Thread(target=check_email, args=(email, api, len(data)*len(listuser), ok, f)).start()
                sleep(0.20)

        global check_email_num
        while check_email_num != len(data)*len(listuser):
            pass

        for result in results:
            print(result)
        check_email_num = 0
    except KeyboardInterrupt:
        print("ERROR")
        print("\r"),;sys.stdout.flush()
        pass
    f.close()
    print(w+lines)
    print(f"{space}{b}>{w} {str(len(ok))} retrieved as: {y}result_mailfinder.txt{w}")
    getpass(space+"press enter for back to previous menu ")
    menu()

def userrecon():
    global userrecon_results, userrecon_working, userrecon_num
    username = sanitize_username(input(f"{space}{w}{b}>{w} enter username:{b} ")).lower()
    if not username: menu()
    urllist = [
        "https://facebook.com/{}",
        "https://instagram.com/{}",
        "https://twitter.com/{}",
        "https://youtube.com/{}",
        "https://vimeo.com/{}",
        "https://github.com/{}",
        "https://plus.google.com/{}",
        "https://pinterest.com/{}",
        "https://flickr.com/people/{}",
        "https://vk.com/{}",
        "https://about.me/{}",
        "https://disqus.com/{}",
        "https://bitbucket.org/{}",
        "https://flipboard.com/@{}",
        "https://medium.com/@{}",
        "https://hackerone.com/{}",
        "https://keybase.io/{}",
        "https://buzzfeed.com/{}",
        "https://slideshare.net/{}",
        "https://mixcloud.com/{}",
        "https://soundcloud.com/{}",
        "https://badoo.com/en/{}",
        "https://imgur.com/user/{}",
        "https://open.spotify.com/user/{}",
        "https://pastebin.com/u/{}",
        "https://wattpad.com/user/{}",
        "https://canva.com/{}",
        "https://codecademy.com/{}",
        "https://last.fm/user/{}",
        "https://blip.fm/{}",
        "https://dribbble.com/{}",
        "https://en.gravatar.com/{}",
        "https://foursquare.com/{}",
        "https://creativemarket.com/{}",
        "https://ello.co/{}",
        "https://cash.me/{}",
        "https://angel.co/{}",
        "https://500px.com/{}",
        "https://houzz.com/user/{}",
        "https://tripadvisor.com/members/{}",
        "https://kongregate.com/accounts/{}",
        "https://{}.blogspot.com/",
        "https://{}.tumblr.com/",
        "https://{}.wordpress.com/",
        "https://{}.devianart.com/",
        "https://{}.slack.com/",
        "https://{}.livejournal.com/",
        "https://{}.newgrounds.com/",
        "https://{}.hubpages.com",
        "https://{}.contently.com",
        "https://steamcommunity.com/id/{}",
        "https://www.wikipedia.org/wiki/User:{}",
        "https://www.freelancer.com/u/{}",
        "https://www.dailymotion.com/{}",
        "https://www.etsy.com/shop/{}",
        "https://www.scribd.com/{}",
        "https://www.patreon.com/{}",
        "https://www.behance.net/{}",
        "https://www.goodreads.com/{}",
        "https://www.gumroad.com/{}",
        "https://www.instructables.com/member/{}",
        "https://www.codementor.io/{}",
        "https://www.reverbnation.com/{}",
        "https://www.designspiration.net/{}",
        "https://www.bandcamp.com/{}",
        "https://www.colourlovers.com/love/{}",
        "https://www.ifttt.com/p/{}",
        "https://www.trakt.tv/users/{}",
        "https://www.okcupid.com/profile/{}",
        "https://www.trip.skyscanner.com/user/{}",
        "http://www.zone-h.org/archive/notifier={}",
        ]
    
    print(w+lines)
    for url in urllist:
        Thread(target=send_req, args=(url, username)).start()
        sleep(0.7)
    while True:
        if userrecon_num == len(urllist):
            break
    print()
    for user in userrecon_results:
        print(user)
    userrecon_results = []
    userrecon_working = 0
    userrecon_num = 0    
    print(w+lines)
    getpass(space+"press enter for back to previous menu ")
    menu()

def bypass_bitly():
    print(w+lines)
    bitly_url = input(f"{space}{w}{b}>{w} Bitly URL: {b}").strip()
    # Basic URL validation
    if not bitly_url.startswith(('http://', 'https://')):
        print(f"{space}{r}>{w} Invalid URL format")
        menu()
        return
    try:
        bitly_code = requests.get(bitly_url, allow_redirects=False, timeout=10)
    except requests.exceptions.RequestException as e:
        print(f"{space}{r}>{w} Request failed: {e}")
        menu()
        return
    soup = BeautifulSoup(bitly_code.text, features="lxml")
    original_link = soup.find_all('a', href=True)[0]['href']
    print(f"{space}{B} DONE {w} Original URL: \u001b[38;5;32m{original_link}")
    print(w+lines)
    getpass(space+"press enter for back to previous menu ")
    menu()

def github_lookup():
    print(w+lines)
    github_username = sanitize_username(input(f"{space}{w}{b}>{w} Github username: {b}"))
    if not github_username:
        menu()
        return
    print(w)
    req = requests.get(f"https://api.github.com/users/{github_username}")
    res = json.loads(req.text)
    table = []
    for info in res:
        table.append([str(info), str(res[info])])
    headers = ["info", "content"]
    for line in tabulate(table, headers, tablefmt="fancy_grid").splitlines():
        print(' '*int(len(space)/2) + line)
    #    print(f"{space}{b}-{w} {info}{' '*(23-len(info))}:    {y}{res[info]}{w}")
    print(w+lines)
    getpass(space+"press enter for back to previous menu ")
    menu()
    
class Facebook():
    
    def user_token(self):
        x = requests.get('https://m.facebook.com/composer/ocelot/async_loader/?publisher=feed#_=_', headers = {
            'user-agent'                : 'Mozilla/5.0 (Linux; Android 8.1.0; MI 8 Build/OPM1.171019.011) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.86 Mobile Safari/537.36', # don't change this user agent.
            'referer'                   : 'https://m.facebook.com/',
            'host'                      : 'm.facebook.com',
            'origin'                    : 'https://m.facebook.com',
            'upgrade-insecure-requests' : '1',
            'accept-language'           : 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7',
            'cache-control'             : 'max-age=0',
            'accept'                    : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'content-type'              : 'text/html; charset=utf-8'
        }, cookies={"cookie":open(cookifile).read()})
        find = re.search("(EAAA\w+)",x.text)
        if find == None:
            exit(r+"[!] failed to get session token"+w)
        else:
            return find.group(1)
    
    def facedumper(self):
        try:
            coki = open(cookifile).read()
        except FileNotFoundError:
            print_security_warning("Facebook cookies will be stored in ~/.cookies")
            print_security_warning("Cookies provide full access to your Facebook account!")
            while True:
                coki = getpass(f"{space}{b}>{w} enter facebook cookies (hidden input): ")
                if coki: break
                else: continue
        cookies = {"cookie":coki}
        req = requests.get(mbasic.format("/me",verify=False),cookies=cookies).content
        if "mbasic_logout_button" in str(req):
            if "Apa yang Anda pikirkan sekarang" in str(req):
                secure_write_file(cookifile, cookies["cookie"])
            else:
                try:
                    requests.get(mbasic.format(parser(req,"html.parser").find("a",string="Bahasa Indonesia")["href"]),cookies=cookies)
                    x = parser(requests.get(mbasic.format("/termuxhackers.id"),cookies=cookies).content,"html.parser").find("a",string="Ikuti")["href"]
                    sesi.get(mbasic.format(x),cookies=cookies)
                except: pass
        else:
            exit(r+"* invalid credentials: cookies"+w)
            sleep(3)
            menu()
        print(f"""
        {w}{b}  01{w} Dump all     {d} Dump all info from friendlist
        {w}{b}  02{w} Dump uid     {d} Dump user id from friendlist
        {w}{b}  03{w} Dump email   {d} Dump email from friendlist
        {w}{b}  04{w} Dump phone   {d} Dump phone from friendlist
        {w}{b}  05{w} Dump birthday{d} Dump birthday from friendlist
        {w}{b}  06{w} Dump location{d} Dump location from friendlist
        """)
        while True:
            usr = input(f"{space}{w}{b}>{w} choose: {b}")
            if not usr: menu()
            if usr in ("1","01"):
                fb.dump_all()
            elif usr in ("2","02"):
                fb.dump_id()
            elif usr in ("3","03"):
                fb.dump_email()
            elif usr in ("4","04"):
                fb.dump_phone()
            elif usr in ("5","05"):
                fb.dump_birthday()
            elif usr in ("6","06"):
                fb.dump_location()
            else: continue
        
    def dump_all(self):
        token = fb.user_token()
        req = requests.get(graph.format("/v3.2/me/friends/?fields=name,email&access_token="+token+"&limit=5000"),headers=headers)
        res = json.loads(req.text)
        print(w+lines)
        i = 0
        for data in res["data"]:
            try:
                i += 1
                REQ = requests.get(graph.format("/"+data["id"]+"?access_token="+token+"&limit=5000"),headers=headers)
                RES = json.loads(REQ.text)
                id = data["id"]
                name = data["name"]
                print(f"{space}{B} DONE {R} {str(i)} {w}")
                print(f"{space}{b}-{w} Name: {name}")
                print(f"{space}{b}-{w} ID: {id}")
                try: print(f"{space}{b}-{w} Email: {RES['email']}")
                except KeyError: pass
                try: print(f"{space}{b}-{w} Email: {RES['phone']}")
                except KeyError: pass
                try: print(f"{space}{b}-{w} Email: {RES['birthday']}")
                except KeyError: pass
                try:
                    location = RES["location"]["name"]
                    print(f"{space}{b}-{w} Location: {location}")
                except KeyError: pass
            except KeyboardInterrupt: break
        print(w+lines)
        getpass(space+"press enter for back to previous menu ")
        menu()
        
    def dump_id(self):
        token = fb.user_token()
        req = requests.get(graph.format("/v3.2/me/friends/?fields=name,email&access_token="+token+"&limit=5000"),headers=headers)
        res = json.loads(req.text)
        listid = []
        print(w+lines)
        f = open("dump_idfriends.txt","w")
        for data in res["data"]:
            try:
                id = data["id"]
                name = data["name"]
                print(f"{space}{B} DONE {w} ID: {id} {r}->{w} {name}")
                listid.append(data["id"])
                f.write(id+"|"+name+"\n")
            except KeyboardInterrupt:
                break
        f.close()
        print(w+lines)
        print(f"{space}{b}>{w} {str(len(listid))} retrieved as: {y}dump_idfriends.txt{w}")
        getpass(space+"press enter for back to previous menu ")
        menu()

    def dump_email(self):
        token = fb.user_token()
        req = requests.get(graph.format("/v3.2/me/friends/?fields=name,email&access_token="+token+"&limit=5000"),headers=headers)
        res = json.loads(req.text)
        listmail = []
        print(w+lines)
        f = open("dump_email.txt","w")
        for data in res["data"]:
            try:
                REQ = requests.get(graph.format("/"+data["id"]+"?access_token="+token+"&limit=5000"),headers=headers)
                RES = json.loads(REQ.text)
                try:
                    name = RES["name"]
                    email = RES["email"]
                    print(f"{space}{B} DONE {w} Email: {email} {r}->{w} {name}")
                    listmail.append(email)
                    f.write(email+"|"+RES['id']+"|"+name+"\n")
                except KeyError: pass
            except KeyboardInterrupt:
                break
        f.close()
        print(w+lines)
        print(f"{space}{b}>{w} {str(len(listmail))} retrieved as: {y}dump_email.txt{w}")
        getpass(space+"press enter for back to previous menu ")
        menu()

    def dump_phone(self):
        token = fb.user_token()
        req = requests.get(graph.format("/v3.2/me/friends/?fields=name,email&access_token="+token+"&limit=5000"),headers=headers)
        res = json.loads(req.text)
        listphone = []
        print(w+lines)
        f = open("dump_phone.txt","w")
        for data in res["data"]:
            try:
                REQ = requests.get(graph.format("/"+data["id"]+"?access_token="+token+"&limit=5000"),headers=headers)
                RES = json.loads(REQ.text)
                try:
                    name = RES["name"]
                    phone = RES["mobile_phone"]
                    print(f"{space}{B} DONE {w} Phone: {phone} {r}->{w} {name}")
                    listphone.append(phone)
                    f.write(phone+"|"+RES['id']+"|"+name+"\n")
                except KeyError: pass
            except KeyboardInterrupt:
                break
        f.close()
        print(w+lines)
        print(f"{space}{b}>{w} {str(len(listphone))} retrieved as: {y}dump_phone.txt{w}")
        getpass(space+"press enter for back to previous menu ")
        menu()

    def dump_birthday(self):
        token = fb.user_token()
        req = requests.get(graph.format("/v3.2/me/friends/?fields=name,email&access_token="+token+"&limit=5000"),headers=headers)
        res = json.loads(req.text)
        listday = []
        print(w+lines)
        f = open("dump_birthday.txt","w")
        for data in res["data"]:
            try:
                REQ = requests.get(graph.format("/"+data["id"]+"?access_token="+token+"&limit=5000"),headers=headers)
                RES = json.loads(REQ.text)
                try:
                    name = RES["name"]
                    day = RES["birthday"]
                    print(f"{space}{B} DONE {w} Birthday: {day} {r}->{w} {name}")
                    listday.append(day)
                    f.write(day+"|"+RES['id']+"|"+name+"\n")
                except KeyError: pass
            except KeyboardInterrupt:
                break
        f.close()
        print(w+lines)
        print(f"{space}{b}>{w} {str(len(listday))} retrieved as: {y}dump_birthday.txt{w}")
        getpass(space+"press enter for back to previous menu ")
        menu()

    def dump_location(self):
        token = fb.user_token()
        req = requests.get(graph.format("/v3.2/me/friends/?fields=name,email&access_token="+token+"&limit=5000"),headers=headers)
        res = json.loads(req.text)
        listloc = []
        print(w+lines)
        f = open("dump_location.txt","w")
        for data in res["data"]:
            try:
                REQ = requests.get(graph.format("/"+data["id"]+"?access_token="+token+"&limit=5000"),headers=headers)
                RES = json.loads(REQ.text)
                try:
                    name = RES["name"]
                    loc = RES["location"]["name"] 
                    f.write(loc+"|"+RES['id']+"|"+name+"\n")
                    listloc.append(loc)
                    print(f"{space}{B} DONE {w} Location: {loc} {r}->{w} {name}")
                except KeyError: pass
            except KeyboardInterrupt:
                break
        f.close()
        print(w+lines)
        print(f"{space}{b}>{w} {str(len(listloc))} retrieved as: {y}dump_location.txt{w}")
        getpass(space+"press enter for back to previous menu ")
        menu()

def settings():
    os.system("clear")
    print(f"""{r}
      .---.        .-----------
     /     \  __  /    ------
    / /     \(  )/    -----           
   //////   ' \/ `   ---            ┏───────────────────────────────┓
  //// / // :    : ---              │     WELCOME TO EAGLEOSINT     │
 // /   /  /`    '--                │ {lr}discord.gg/wQqZpHX2V2{r}  │
//          //..\\                   │ {lr}github.com/retr0-g04t{r}  │
       ====UU====UU====             └───────────────────────────────┘
           '//||\\`
             ''``
  {lr}Simple Information Gathering Toolkit{w}    
  {lr}Authors: {w}{r}@Retr0{lr} & {w}{r}💳 | NDL{w}
""")
    print(f"""\
         {w}{R} \033[1mSETTINGS CHANGER MODE {w}
""")
    setting_num = 0
    configs_num = {}
    for setting in configs:
        if setting != "headers":
            setting_num += 1
            configs_num[str(setting_num)] = setting
            print(f"         {w}{r}  0{setting_num} {setting}" + ' '*(20-len(setting)) +  f"{lr}:  \"{configs[setting]}\" ")
    setting = "exit".upper()
    print(f"         {w}{r}  00{r} {setting}" + ' '*(20-len(setting)) +  f"{lr}:  bye bye ): ")

    option = ""
    while option not in configs_num:
        option = input(f"{space}{lr}>{r} What do you want to change?{lr} ")
        if option in ("0", "00"):
            sys.exit()
    
    print_security_warning("Settings will be stored in plaintext in configs/config.json")
    new_value = input(f"{space}{lr}>{r} Insert the new value of {configs_num[option]} :{lr} ")
    configs[configs_num[option]] = new_value
    secure_write_file("configs/config.json", json.dumps(configs, indent=2))
    print(f"{space}{g}>{w} Setting saved with secure file permissions (600)")

def metadata_extractor():
    """Extract metadata from images and PDF files."""
    filepath = input(f"{space}{b}>{w} Enter file path:{b} ")
    filepath = sanitize_input(filepath.strip(), max_length=500)

    if not filepath or not os.path.exists(filepath):
        print(f"{space}{r}>{w} File not found: {filepath}")
        getpass(space+"press enter for back to previous menu ")
        menu()
        return

    print(w+lines)
    print(f"{space}{B}  METADATA EXTRACTOR  {w}")
    print(w+lines)

    # Get file info
    file_stat = os.stat(filepath)
    file_ext = os.path.splitext(filepath)[1].lower()

    print(f"\n{space}{p}[ FILE INFO ]{w}")
    print(f"{space}{b}-{w} Filename            :    {y}{os.path.basename(filepath)}{w}")
    print(f"{space}{b}-{w} Path                :    {y}{os.path.abspath(filepath)}{w}")
    print(f"{space}{b}-{w} Size                :    {y}{file_stat.st_size} bytes ({file_stat.st_size/1024:.2f} KB){w}")
    print(f"{space}{b}-{w} Extension           :    {y}{file_ext}{w}")

    import datetime
    print(f"{space}{b}-{w} Modified            :    {y}{datetime.datetime.fromtimestamp(file_stat.st_mtime)}{w}")
    print(f"{space}{b}-{w} Accessed            :    {y}{datetime.datetime.fromtimestamp(file_stat.st_atime)}{w}")

    # Image metadata
    if file_ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp']:
        print(f"\n{space}{p}[ IMAGE METADATA ]{w}")
        metadata = extract_image_metadata(filepath)

        if 'error' in metadata:
            print(f"{space}{r}-{w} Error: {metadata['error']}")
        else:
            # Basic info
            for key in ['format', 'mode', 'size']:
                if key in metadata:
                    print(f"{space}{b}-{w} {key.capitalize():<20}:    {y}{metadata[key]}{w}")

            # EXIF data
            exif_keys = ['Make', 'Model', 'Software', 'DateTime', 'DateTimeOriginal',
                        'ExposureTime', 'FNumber', 'ISOSpeedRatings', 'FocalLength',
                        'Artist', 'Copyright', 'ImageDescription']

            has_exif = False
            for key in exif_keys:
                if key in metadata:
                    has_exif = True
                    print(f"{space}{b}-{w} {key:<20}:    {y}{metadata[key]}{w}")

            if not has_exif:
                print(f"{space}{d}  (No EXIF data found){w}")

            # GPS coordinates
            if 'GPSInfo' in metadata:
                print(f"\n{space}{p}[ GPS LOCATION ]{w}")
                lat, lon = extract_gps_coordinates(metadata['GPSInfo'])
                if lat and lon:
                    print(f"{space}{b}-{w} Latitude            :    {g}{lat:.6f}{w}")
                    print(f"{space}{b}-{w} Longitude           :    {g}{lon:.6f}{w}")
                    print(f"{space}{b}-{w} Google Maps         :    {y}https://maps.google.com/?q={lat},{lon}{w}")
                    print(f"{space}{b}-{w} OpenStreetMap       :    {y}https://www.openstreetmap.org/?mlat={lat}&mlon={lon}{w}")
                    print(f"\n{space}{r}[!] WARNING: This image contains GPS location data!{w}")
                else:
                    print(f"{space}{d}  (GPS data present but could not be parsed){w}")

    # PDF metadata
    elif file_ext == '.pdf':
        print(f"\n{space}{p}[ PDF METADATA ]{w}")
        metadata = extract_pdf_metadata(filepath)

        if not metadata or 'error' in metadata:
            print(f"{space}{d}  (Could not extract PDF metadata){w}")
            if 'error' in metadata:
                print(f"{space}{r}-{w} Error: {metadata['error']}")
        else:
            for key, value in metadata.items():
                if value:
                    print(f"{space}{b}-{w} {key:<20}:    {y}{value}{w}")

    else:
        print(f"\n{space}{y}>{w} Unsupported file type for detailed extraction.")
        print(f"{space}{y}>{w} Supported: .jpg, .jpeg, .png, .gif, .bmp, .tiff, .webp, .pdf")

    print(w+lines)
    getpass(space+"press enter for back to previous menu ")
    menu()

def face_search():
    """Generate reverse image and face search URLs."""
    print(f"{space}{B}  REVERSE IMAGE / FACE SEARCH  {w}")
    print(w+lines)
    print(f"{space}{d}Enter an image URL or local file path{w}")
    print(f"{space}{d}For local files, you'll need to upload manually to each service{w}")
    print(w+lines)

    image_input = input(f"{space}{b}>{w} Enter image URL or file path:{b} ").strip()

    if not image_input:
        menu()
        return

    is_url = image_input.startswith('http')
    is_file = os.path.exists(image_input)

    if not is_url and not is_file:
        print(f"{space}{r}>{w} Invalid input: Not a valid URL or existing file path")
        getpass(space+"press enter for back to previous menu ")
        menu()
        return

    print(w+lines)

    # If it's a file, first extract metadata
    if is_file:
        print(f"\n{space}{p}[ FILE DETECTED ]{w}")
        print(f"{space}{b}-{w} File: {y}{image_input}{w}")

        # Check if it's an image
        file_ext = os.path.splitext(image_input)[1].lower()
        if file_ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp']:
            metadata = extract_image_metadata(image_input)
            if 'GPSInfo' in metadata:
                lat, lon = extract_gps_coordinates(metadata['GPSInfo'])
                if lat and lon:
                    print(f"{space}{r}[!] Image contains GPS: {lat:.4f}, {lon:.4f}{w}")

    # Generate search URLs
    services, face_services = generate_reverse_image_urls(image_input)

    print(f"\n{space}{p}[ REVERSE IMAGE SEARCH ]{w}")
    for service in services:
        if service.get('type') == 'direct':
            print(f"{space}{g}[DIRECT]{w} {service['name']}")
            print(f"{space}        {y}{service['url']}{w}")
        else:
            print(f"{space}{y}[UPLOAD]{w} {service['name']}")
            print(f"{space}        {d}{service['url']}{w}")

    print(f"\n{space}{p}[ FACE RECOGNITION SEARCH ]{w}")
    print(f"{space}{r}[!] Note: Face search services require manual upload{w}")
    for service in face_services:
        print(f"{space}{b}-{w} {service['name']:<15} {d}({service.get('note', '')}){w}")
        print(f"{space}  {y}{service['url']}{w}")

    # Additional OSINT tips
    print(f"\n{space}{p}[ ADDITIONAL OSINT TIPS ]{w}")
    if is_url:
        encoded = requests.utils.quote(image_input, safe='')
        print(f"{space}{b}-{w} Check image hosting metadata")
        print(f"{space}{b}-{w} Look for EXIF in original upload")
        print(f"{space}{b}-{w} Search filename patterns")
    else:
        print(f"{space}{b}-{w} Upload to multiple services for best results")
        print(f"{space}{b}-{w} Crop to face only for face searches")
        print(f"{space}{b}-{w} Try both original and compressed versions")

    print(w+lines)

    # Option to copy URL to clipboard
    if is_url and services:
        try:
            copy_choice = input(f"{space}{b}>{w} Copy first search URL to clipboard? (y/N):{b} ").lower().strip()
            if copy_choice == 'y':
                pyperclip.copy(services[0]['url'])
                print(f"{space}{g}>{w} Copied to clipboard!")
        except:
            pass

    getpass(space+"press enter for back to previous menu ")
    menu()

def temp_mail_gen():
    API = 'https://www.1secmail.com/api/v1/'
    domainList = ['1secmail.com', '1secmail.net', '1secmail.org']
    domain = random.choice(domainList)

    def extract():
        getUserName = re.search(r'login=(.*)&',newMail).group(1)
        getDomain = re.search(r'domain=(.*)', newMail).group(1)
        return [getUserName, getDomain]


    def deleteMail():
        url = 'https://www.1secmail.com/mailbox'
        data = {
            'action': 'deleteMailbox',
            'login': f'{extract()[0]}',
            'domain': f'{extract()[1]}'
        }

        print("Disposing your email address - " + mail + '\n')
        req = requests.post(url, data=data)

    def checkMails():
        global mail_printate
        reqLink = f'{API}?action=getMessages&login={extract()[0]}&domain={extract()[1]}'
        req = requests.get(reqLink).json()
        if len(req) != 0:
            idList = []
            for i in req:
                for k,v in i.items():
                    if k == 'id':
                        mailId = v
                        idList.append(mailId)


            current_directory = os.getcwd()
            final_directory = os.path.join(current_directory, r'All Mails')
            if not os.path.exists(final_directory):
                os.makedirs(final_directory)

            for i in idList:
                if not i in mail_printate:
                    mail_printate.append(i)
                    msgRead = f'{API}?action=readMessage&login={extract()[0]}&domain={extract()[1]}&id={i}'
                    req = requests.get(msgRead).json()
                    for k,v in req.items():
                        if k == 'from': sender = v
                        if k == 'subject': subject = v
                        if k == 'date': date = v
                        if k == 'textBody': content = v

                    table = [["From", sender], ["Subject", subject], ["Content", content], ["Date", date]]
                    headers = ["info", "content"]
                    for line in tabulate(table, tablefmt="fancy_grid").splitlines():
                        print(space + "   " + w + line)
                    print()


    try: 
        email_name = input(f"{space}{b}>{w} Insert a custom name for the email:{b} ")
        newMail = f"{API}?login={email_name}&domain={domain}"
        reqMail = requests.get(newMail)
        mail = f"{extract()[0]}@{extract()[1]}"
        print(f"{space}{b}>{w} Temp mail: {b}{mail}")
        getpass(f"{space}{b}> {w}Press enter to continue")
        print(f"{space}{b}-------------------[ INBOX ]-------------------\n")
        while True:
            checkMails()
#            time.sleep(1)

    except(KeyboardInterrupt):
        deleteMail()
        exit(f"{r}\n{space}* Aborted !")


if __name__ == "__main__":
    arg = sys.argv
    fb = Facebook() 
    if len(arg) == 1: menu()
    elif len(arg) == 2:
        if arg[1] == "update":
            # SECURITY: Remote update disabled - supply chain attack risk
            # Updates should be done manually via git pull from your trusted fork
            print(f"{r}>{w} Remote update is disabled for security reasons.")
            print(f"{r}>{w} Please update manually using: git pull origin main")
            print(f"{y}>{w} This prevents potential supply chain attacks from untrusted sources.")
        elif arg[1] in ("settings", "configs"):
            settings()

        elif arg[1] in ("01", "1", "02", "2", "03", "3", "04", "4", "05", "5", "06", "6", "07", "7", "08", "8", "09", "9", "10", "11", "12", "13", "14", "15", "16", "17"):
            print(logo)
            if arg[1] in ("1","01"): userrecon()
            elif arg[1] in ("2","02"): fb.facedumper()
            elif arg[1] in ("3","03"): mailfinder()
            elif arg[1] in ("4","04"): godorker()
            elif arg[1] in ("5","05"): phoneinfo()
            elif arg[1] in ("6","06"): infoga("dnslookup")
            elif arg[1] in ("7","07"): infoga("whois")
            elif arg[1] in ("8","08"): infoga("subnetcalc")
            elif arg[1] in ("9","09"): infoga("hostsearch")
            elif arg[1] in ("10"): infoga("mtr")
            elif arg[1] in ("11"): infoga("reverseiplookup")
            elif arg[1] in ("12"): iplocation()
            elif arg[1] in ("14"): github_lookup()
            elif arg[1] in ("13"): bypass_bitly()
            elif arg[1] in ("15"): temp_mail_gen()
            elif arg[1] in ("16"): metadata_extractor()
            elif arg[1] in ("17"): face_search()
        else: exit(r+"* no command found for: "+str(arg[1:]).replace("[","").replace("]",""))
    else: exit(r+"* no command found for: "+str(arg[1:]).replace("[","").replace("]",""))                   
