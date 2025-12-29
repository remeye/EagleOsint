# CLAUDE.md - EagleOsint

## Project Overview

EagleOsint is an Open Source Intelligence (OSINT) toolkit designed for information gathering. It provides a command-line interface with multiple reconnaissance and lookup tools for security research and educational purposes.

**Authors:** @Retr0 & NDL
**License:** GPL-3.0
**Version:** 1.1

## Codebase Structure

```
EagleOsint/
├── EagleOsint.py       # Main application (single-file architecture)
├── configs/
│   └── config.json     # API keys and configuration
├── image/              # Logo and documentation images
├── linuxinstall.sh     # Linux installation script
├── LICENSE             # GPL-3.0 license
└── README.md           # User documentation
```

## Key Architecture Decisions

### Single-File Design
The entire application is contained in `EagleOsint.py` (~857 lines). This design choice prioritizes:
- Easy distribution and installation
- Simple deployment on various systems
- No complex import structures

### Menu-Driven CLI
The application uses a numeric menu system accessible via the `menu()` function. Users select features by number (01-17).

### Threading Model
Network-intensive operations (username recon, email validation) use Python's `threading.Thread` for concurrent requests, improving performance when checking multiple URLs/emails.

## Features Map

| Option | Function | Description |
|--------|----------|-------------|
| 01 | `userrecon()` | Username search across 71 social platforms |
| 02 | `fb.facedumper()` | Facebook data extraction (requires cookies) |
| 03 | `mailfinder()` | Email discovery and validation |
| 04 | `godorker()` | Google dork search automation |
| 05 | `phoneinfo()` | Phone number lookup (Veriphone API) |
| 06 | `infoga("dnslookup")` | DNS record lookup |
| 07 | `infoga("whois")` | WHOIS domain information |
| 08 | `infoga("subnetcalc")` | Subnet calculation |
| 09 | `infoga("hostsearch")` | Host discovery |
| 10 | `infoga("mtr")` | MTR traceroute lookup |
| 11 | `infoga("reverseiplookup")` | Reverse IP lookup |
| 12 | `iplocation()` | IP geolocation (ipinfo.io) |
| 13 | `bypass_bitly()` | Bitly URL resolver |
| 14 | `github_lookup()` | GitHub user information |
| 15 | `temp_mail_gen()` | Temporary email generation (1secmail.com) |
| 16 | `metadata_extractor()` | Extract EXIF/metadata from images and PDFs |
| 17 | `face_search()` | Reverse image and face recognition search |

## Dependencies

### System Packages
- `libxml2`
- `libxslt`
- `python3`
- `python3-pip`

### Python Packages
```
requests
lxml
beautifulsoup4
tabulate
pyperclip
Pillow          # For image metadata extraction
```

## Configuration

Configuration is stored in `configs/config.json`:

```json
{
  "headers": {"User-Agent": "..."},
  "real-email-api-key": "",
  "veriphone-api-key": ""
}
```

### Required API Keys
- **Veriphone API** (https://veriphone.io) - For phone number lookups
- **IsItARealEmail API** (https://isitarealemail.com) - For email validation

API keys can be configured via:
1. Direct edit of `configs/config.json`
2. Running `python3 EagleOsint.py configs`
3. Interactive prompt on first use of feature

## External APIs Used

| API | Purpose | Base URL |
|-----|---------|----------|
| HackerTarget | DNS, WHOIS, Host lookups | `api.hackertarget.com` |
| ipinfo.io | IP geolocation | `ipinfo.io` |
| Veriphone | Phone validation | `api.veriphone.io` |
| IsItARealEmail | Email validation | `isitarealemail.com` |
| Facebook Graph | FB data extraction | `graph.facebook.com` |
| GitHub API | User info lookup | `api.github.com` |
| 1secmail | Temporary emails | `1secmail.com` |

## Running the Application

### Standard Launch
```bash
python3 EagleOsint.py
```

### Direct Feature Access
```bash
python3 EagleOsint.py 01    # Run userrecon directly
python3 EagleOsint.py 05    # Run phoneinfo directly
```

### Configuration Mode
```bash
python3 EagleOsint.py configs   # Modify API keys
python3 EagleOsint.py settings  # Same as configs
```

### Update
```bash
# Remote update is DISABLED for security - use git instead:
git pull origin main
```

## Code Conventions

### Color Codes
Terminal colors are defined as global variables:
- `r` - Red (`\033[31m`)
- `g` - Green (`\033[32m`)
- `y` - Yellow (`\033[33m`)
- `b` - Blue (`\033[34m`)
- `p` - Purple (`\033[35m`)
- `d` - Dim (`\033[2;37m`)
- `w` - Reset/White (`\033[0m`)

Background colors: `W`, `R`, `G`, `Y`, `B` (uppercase variants)

### Output Formatting
- `space` variable provides consistent left padding
- `lines` variable creates divider lines
- `display_progress()` for progress bars

### Error Handling Pattern
Most functions catch:
- `KeyboardInterrupt` - User abort
- `requests.exceptions.*` - Network errors
- `KeyError` - Missing API response fields

### Navigation Pattern
Functions typically end with:
```python
getpass(space+"press enter for back to previous menu ")
menu()
```

## Output Files

Several features write results to files in the working directory:
- `result_godorker.txt` - Google dork results
- `result_mailfinder.txt` - Valid emails found
- `dump_idfriends.txt` - Facebook friend IDs
- `dump_email.txt` - Facebook friend emails
- `dump_phone.txt` - Facebook friend phones
- `dump_birthday.txt` - Facebook friend birthdays
- `dump_location.txt` - Facebook friend locations

## Facebook Integration

The `Facebook` class handles Facebook-specific operations:
- Requires cookie authentication stored in `~/.cookies`
- Uses both mbasic (mobile) and Graph API endpoints
- Token extraction via regex from composer endpoint

## Development Notes

### Adding New Features
1. Create a new function following existing patterns
2. Add menu entry in `menu()` function
3. Add handler in `mainmenu()` while loop
4. Add CLI shortcut in `__main__` argument handling

### Testing API Endpoints
Test keys are provided in README.md for development:
- Veriphone: `47703D994B174BACBDC5AD734CC381B4`
- Real-email: `0c6ad1fd-f753-4628-8c0a-7968e722c6c7`

### Common Patterns

**API Request Pattern:**
```python
req = requests.get(url, headers=headers)
res = json.loads(req.text)
for info in res:
    print(f"{space}{b}-{w} {info}: {res[info]}")
```

**Threaded Operation Pattern:**
```python
for item in items:
    Thread(target=process_item, args=(item,)).start()
    sleep(0.2)  # Rate limiting
```

## Security Measures

This fork includes security hardening compared to the original repository:

### Input Sanitization
All user inputs are now sanitized using dedicated functions:
- `sanitize_input()` - General input sanitization (removes control chars, limits length)
- `sanitize_username()` - Alphanumeric + `_.-` only, max 100 chars
- `sanitize_domain()` - Domain/IP characters only, max 255 chars
- `sanitize_phone()` - Digits and `+` only, max 20 chars
- `sanitize_email()` - Email characters only, max 254 chars

### Secure File Permissions
Sensitive files are now written with owner-only permissions (600):
- `configs/config.json` - API keys
- `~/.cookies` - Facebook session cookies
- Uses `secure_write_file()` and `set_secure_permissions()` functions

### Disabled Remote Update
The original `update` command downloaded code from an external repository, creating a supply chain attack vector. This has been **disabled**. Updates should be done via:
```bash
git pull origin main
```

### Security Warnings
Users are now warned when:
- Storing API keys in config files
- Storing Facebook cookies
- Revealing their public IP address (now opt-in)

### URL Validation
The Bitly bypass function now validates URLs before making requests.

## Remaining Security Considerations

- API keys are still stored in plaintext (but with restricted file permissions)
- Facebook cookies are still stored locally (but with restricted file permissions)
- Rate limiting via `sleep()` calls between requests
- External API calls transmit data to third-party services

## Disclaimer

This tool is intended for educational and authorized security research purposes only. Users are responsible for ensuring they have proper authorization before conducting any reconnaissance activities.
