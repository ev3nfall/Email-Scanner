import sys
import io
import time
import extract_msg
from urlextract import URLExtract
from virustotal_python import Virustotal

VT_API_KEY = "insert key here"

RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RESET = "\033[0m"

def scanURLS(urls):

    def defang(url):
        return url.replace("://", "[://]")
    
    vt = Virustotal(API_KEY=VT_API_KEY)
    verdict = f"\n"
    num = 0
    for url in urls:
        num+=1
        res = vt.request("urls", data={"url": url}, method="POST")
        analysis_id = res.json()["data"]["id"]

        while True:
            report = vt.request(f"analyses/{analysis_id}", method="GET").json()
            status = report["data"]["attributes"]["status"]
            if status == "completed":
                break
            time.sleep(2)

        data = report["data"]["attributes"]["stats"]
        malicious = data["malicious"] > 0
        suspicious = data["suspicious"] > 0
        if malicious:
            verdict += f"\n{RED}Warning: {data["malicious"]} vendor(s) flagged {defang(url)} as malicious.{RESET}"
        if suspicious:
            verdict += f"\n{YELLOW}Warning: {data["suspicious"]} vendor(s) flagged {defang(url)} as suspicious.{RESET}"
    
    if verdict != "\n":
        return verdict
    else:
        return f"{GREEN}{num} URL(s) scanned. No problems detected.{RESET}"
        
def scanAttachments(attachments):
    vt = Virustotal(API_KEY="f5c3369c638010a8be3652bad4b5ad9256ab9f745efa795d81c3f9266881355f")
    verdict = f"\n"
    num = 0
    for att in attachments:
        num+=1
        file_bytes = io.BytesIO(att.data)
        filename = att.longFilename

        res = vt.request("files", files={"file": file_bytes}, method="POST")
        analysis_id = res.json()["data"]["id"]

        while True:
            report = vt.request(f"analyses/{analysis_id}", method="GET").json()
            status = report["data"]["attributes"]["status"]
            if status == "completed":
                break
            time.sleep(2)

        data = report["data"]["attributes"]["stats"]
        malicious = data["malicious"] > 0
        suspicious = data["suspicious"] > 0
        if malicious:
            verdict += f"\n{RED}Warning: {data["malicious"]} vendor(s) flagged [{filename}] as malicious.{RESET}"
        if suspicious:
            verdict += f"\n{YELLOW}Warning: {data["suspicious"]} vendor(s) flagged [{filename}] as suspicious.{RESET}"
    
    if verdict != "\n":
        return verdict
    else:
        return f"{GREEN}{num} attachment(s) scanned. No problems detected.{RESET}"
                       
def generateReport(msg, url_verdict, att_verdict):
    if msg.header.get("Reply-To"):
        reply_to = msg.header.get("Reply-To")
    else:
        reply_to = "None"

    report = f"""
    ***** START OF REPORT *****

    From: {msg.sender}
    To: {msg.to}
    Reply-To: {reply_to}
    Subject: {msg.subject}

    URL scan results --> {url_verdict}

    Attachment scan results --> {att_verdict}

    ***** END OF REPORT *****
    """

    print(report)

def main():

    # Parse email
    mail_file = sys.argv[1]
    msg = extract_msg.Message(mail_file)
    attachments = msg.attachments
    body = msg.body
    extractor = URLExtract()
    urls = extractor.find_urls(body)

    # Analyze links
    if (len(urls) > 0):
        url_verdict = scanURLS(urls)
    else:
        url_verdict = f"No URLs to scan."
    
    # Analyze attachments
    if (len(attachments) > 0):
        att_verdict = scanAttachments(attachments)
    else:
        att_verdict = f"No attachments to scan."

    # Print final report
    generateReport(msg, url_verdict, att_verdict)

if __name__ == "__main__":
    main()
