# Email-Scanner
Python script that takes a .msg file and will check URLs and attachments for malicious content using Virus Total's API

1. Download necessary dependencies

`pip install extract_msg urlextract virustotal-python`

2. Go to `https://www.virustotal.com`, create a free account, and copy your API key. Replace on line 8 of `email_scan.py`

3. Run script

`email_scan.py <msg filename>`
