import time
import requests
import json
import sys
import os
from datetime import datetime
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager

# ================= CONFIGURATION =================
# Path to your PACKED extension file (.crx)
# Make sure this path is 100% correct.
EXTENSION_PATH = r"C:\Users\ASUS\Downloads\Browsec.crx" 

# ================= LOGGING SYSTEM =================
class Logger:
    """Handles writing output to both console and a dynamic file."""
    def __init__(self):
        # Create a dynamic filename based on current timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.filename = f"vpn_rpki_validation_report_{timestamp}.txt"
        self.file = open(self.filename, "w", encoding="utf-8")
        print(f"[*] Report will be saved to: {self.filename}")

    def log(self, message):
        """Print to console and write to file."""
        print(message)
        self.file.write(message + "\n")
        self.file.flush() # Ensure data is written immediately

    def close(self):
        self.file.close()

# ================= HELPER FUNCTIONS =================
def get_ip_details(driver, logger):
    """Fetches the current public IP seen by the browser."""
    try:
        driver.get("https://api.ipify.org?format=json")
        # specific waiting might be needed if internet is slow, but explicit wait is better
        time.sleep(2) 
        ip_data = json.loads(driver.find_element("tag name", "body").text)
        return ip_data['ip']
    except Exception as e:
        logger.log(f"[!] Error fetching IP: {e}")
        return None

def check_rpki_status_external(ip_address, logger):
    """
    Forensic Check: Queries RIPEstat to see if the VPN's IP prefix 
    is RPKI Valid, Invalid, or Unknown.
    """
    logger.log(f"\n[*] Analysing Network Infrastructure for IP: {ip_address}...")
    
    # Step 1: Get Network Info (ASN and Prefix)
    net_info_url = f"https://stat.ripe.net/data/network-info/data.json?resource={ip_address}"
    try:
        response = requests.get(net_info_url).json()
        prefix = response['data']['prefix']
        asns = response['data']['asns']
        
        if not asns:
            logger.log("    [!] No ASN found for this IP. Analysis halted.")
            return "ERROR"
            
        asn = asns[0] # Take the first announcing ASN
        logger.log(f"    > Announced Prefix: {prefix}")
        logger.log(f"    > Origin ASN: AS{asn}")
    except Exception as e:
        logger.log(f"    [!] Could not fetch network info: {e}")
        return "ERROR"

    # Step 2: Check RPKI Validation Status for this Prefix/ASN pair
    rpki_url = f"https://stat.ripe.net/data/rpki-validation/data.json?resource={asn}&prefix={prefix}"
    try:
        rpki_data = requests.get(rpki_url).json()
        status = rpki_data['data']['status']
        return status
    except Exception as e:
        logger.log(f"    [!] Could not validate RPKI: {e}")
        return "ERROR"

def check_rpki_enforcement(driver, logger):
    """
    Security Check: Can the browser reach an RPKI-Invalid domain?
    """
    logger.log("\n[*] Testing VPN RPKI Enforcement Policy...")
    try:
        # We set a short timeout. If the VPN drops the packet, it will timeout or fail.
        # If the page loads, the VPN is NOT enforcing RPKI.
        driver.set_page_load_timeout(8)
        driver.get("https://invalid.rpki.cloudflare.com")
        
        # Check for specific success indicator (Cloudflare's invalid page has text)
        page_text = driver.find_element("tag name", "body").text
        if "RPKI" in page_text or "Cloudflare" in page_text:
             return False # Loaded successfully -> FAIL
        return False
    except Exception as e:
        # If it throws an error (Timeout, Connection Refused), that is GOOD.
        # It means the VPN/ISP blocked the route.
        logger.log(f"    > Connection blocked/timed out as expected ({str(e)[:50]}...).")
        return True 

# ================= MAIN EXECUTION =================
def main():
    # Verify file exists first
    if not os.path.exists(EXTENSION_PATH):
        print(f"Error: The file {EXTENSION_PATH} was not found.")
        print("Please check the path and try again.")
        sys.exit(1)

    logger = Logger()
    logger.log("--- VPN Extension RPKI Forensic Tool ---")

    # 1. Setup Chrome with Extension
    chrome_options = Options()
    
    # CRITICAL FIX: Use add_extension for .crx files
    chrome_options.add_extension(EXTENSION_PATH)
    
    logger.log(f"[*] Loading extension from: {EXTENSION_PATH}")
    
    driver = webdriver.Chrome(
        service=Service(ChromeDriverManager().install()), 
        options=chrome_options
    )

    try:
        # 2. User Interaction Phase
        logger.log("\n[!] ACTION REQUIRED: The browser is now open.")
        logger.log("    1. Pin the extension if needed.")
        logger.log("    2. Open the extension popup.")
        logger.log("    3. CLICK 'CONNECT' / turn the VPN ON.")
        
        # Simple loop to wait for user confirmation
        while True:
            # Using input inside IDEs can be tricky, ensure your terminal supports it
            user_input = input("\n>>> Have you connected the VPN? (y/n): ").lower()
            if user_input == 'y':
                break
            print("Waiting for user confirmation...")

        # 3. Get VPN Exit IP
        vpn_ip = get_ip_details(driver, logger)
        if not vpn_ip:
            logger.log("[!] Critical Error: Could not verify connectivity.")
            return

        logger.log(f"[*] VPN Connection Detected. Exit IP: {vpn_ip}")

        # 4. Perform Forensic RPKI Analysis
        infrastructure_status = check_rpki_status_external(vpn_ip, logger)
        
        # 5. Perform Enforcement Analysis
        enforcement_active = check_rpki_enforcement(driver, logger)

        # ================= REPORT =================
        logger.log("\n" + "="*40)
        logger.log("       MALICIOUS IDENTIFICATION REPORT       ")
        logger.log("="*40)
        
        logger.log(f"VPN Exit Node: {vpn_ip}")
        logger.log(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Result 1: Infrastructure Legitimacy
        logger.log(f"\n1. INFRASTRUCTURE INTEGRITY (RPKI Status):")
        if infrastructure_status == "valid":
            logger.log(f"   [PASS] VALID. The network route is signed and legitimate.")
        elif infrastructure_status == "invalid":
            logger.log(f"   [CRITICAL FAIL] INVALID. This IP prefix conflicts with the real owner's ROA.")
            logger.log(f"   [!!!] HIGH PROBABILITY OF BGP HIJACKING OR SPOOFING.")
        else:
            logger.log(f"   [WARN] UNKNOWN. No ROA found.")

        # Result 2: Security Policy
        logger.log(f"\n2. SECURITY ENFORCEMENT:")
        if enforcement_active:
            logger.log(f"   [PASS] STRICT. The VPN blocked connection to an invalid RPKI route.")
        else:
            logger.log(f"   [FAIL] PERMISSIVE. The VPN allowed connection to a BGP-invalid route.")
            
        logger.log("="*40)
        logger.log(f"\nReport saved to: {logger.filename}")

    except Exception as e:
        logger.log(f"\n[!] An error occurred: {e}")
    finally:
        logger.close()
        input("\nPress Enter to close the browser...")
        driver.quit()

if __name__ == "__main__":
    main()