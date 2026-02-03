import win32evtlog
import xml.etree.ElementTree as ET
import psutil
import time
import os
import subprocess
import requests
import datetime
import json
import sys
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By

# --- CONFIGURATION ---
ITERATIONS = 5
VPN_SETUP_TIME = 120  
TARGET_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "baidu.com", "wikipedia.org",
    "qq.com", "taobao.com", "yahoo.com", "tmall.com", "amazon.com",
    "google.co.in", "twitter.com", "sohu.com", "jd.com", "live.com",
    "instagram.com", "sina.com.cn", "weibo.com", "yandex.ru", "vk.com",
    "reddit.com", "login.tmall.com", "blogspot.com", "ebay.com", "netflix.com",
    "csdn.net", "yahoo.co.jp", "t.co", "bing.com", "twitch.tv",
    "alipay.com", "microsoft.com", "stackoverflow.com", "aliexpress.com", "naver.com",
    "ok.ru", "apple.com", "github.com", "chinadaily.com.cn", "imdb.com",
    "whatsapp.com", "office.com", "google.co.jp", "google.com.br", "pinterest.com",
    "xinhuanet.com", "google.de", "paypal.com", "bilibili.com", "adobe.com",
    "ae35f.hash-test.com", "b890a.hash-test.com", "c123d.hash-test.com", "d456e.hash-test.com"
]

def get_real_ip_from_python():
    """Gets the baseline IP (ISP) to compare against."""
    try:
        return requests.get("https://api.ipify.org", timeout=5).text.strip()
    except:
        return "Unknown"

def get_browser_ip(driver):
    """Gets the IP Chrome is actually using."""
    try:
        driver.get("https://api.ipify.org")
        time.sleep(1)
        return driver.find_element(By.TAG_NAME, "body").text.strip()
    except:
        return "Unknown"

def clear_caches(driver):
    try:
        subprocess.run(["ipconfig", "/flushdns"], stdout=subprocess.DEVNULL)
    except:
        pass
    try:
        driver.get("chrome://net-internals/#dns")
        driver.execute_script("document.getElementById('dns-view-clear-cache').click();")
    except:
        pass

def check_sysmon_globally(domain, lookback_seconds=3):
    """
    Checks Sysmon Event 22 for ANY process.
    """
    xpath_query = f"""
    <QueryList>
      <Query Id="0" Path="Microsoft-Windows-Sysmon/Operational">
        <Select Path="Microsoft-Windows-Sysmon/Operational">
          *[System[(EventID=22) and TimeCreated[timediff(@SystemTime) &lt;= {lookback_seconds * 1000}]]]
          and
          *[EventData[Data[@Name='QueryName']='{domain}' or Data[@Name='QueryName']='www.{domain}']]
        </Select>
      </Query>
    </QueryList>
    """
    
    try:
        log_handle = win32evtlog.EvtQuery(
            "Microsoft-Windows-Sysmon/Operational",
            win32evtlog.EvtQueryChannelPath,
            xpath_query
        )
        events = win32evtlog.EvtNext(log_handle, 10)
        
        if events:
            for event in events:
                xml_content = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                return xml_content
    except Exception:
        pass
        
    return None

def generate_final_txt_report(real_ip, ip_history, leak_history):
    """
    Generates a single TXT report at the end of execution.
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"Final_Leak_Report_{timestamp}.txt"
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write("==================================================\n")
        f.write(f"           FINAL VPN LEAK TEST REPORT             \n")
        f.write(f"           Generated: {timestamp}\n")
        f.write("==================================================\n\n")
        
        # --- SECTION 1: NETWORK IDENTITY ---
        f.write("--- [1] NETWORK IDENTITY ---\n")
        f.write(f"Baseline ISP IP: {real_ip}\n")
        f.write(f"IPs Detected During Test: {', '.join(set(ip_history))}\n")
        
        if real_ip in ip_history:
             f.write("STATUS: [CRITICAL] REAL IP DETECTED DURING TEST!\n")
        else:
             f.write("STATUS: [SECURE] Real IP was hidden throughout the test.\n")
        f.write("\n")

        # --- SECTION 2: DOMAIN LEAK ANALYSIS ---
        f.write("--- [2] DOMAIN LEAK ANALYSIS ---\n")
        f.write("Note: If a domain is marked LEAK below, it leaked at least once during the test.\n\n")
        
        leak_count = 0
        
        for domain in TARGET_DOMAINS:
            # Check if this domain exists in our history of leaks
            if domain in leak_history:
                leak_count += 1
                f.write(f"[!] LEAK DETECTED: {domain}\n")
                # List every instance of the leak found
                for event in leak_history[domain]:
                    f.write(f"    -> Time: {event['time']} | Source: {event['source']} | PID: {event['pid']}\n")
                f.write("-" * 40 + "\n")
            else:
                f.write(f"[✓] SAFE: {domain}\n")
        
        f.write(f"\nTotal Domains Tested: {len(TARGET_DOMAINS)}\n")
        f.write(f"Total Leaking Domains: {leak_count}\n")
        f.write("==================================================\n")

    print(f"\n\n[+] FINAL REPORT GENERATED: {filename}")
    print(f"[+] Total Leaking Domains: {leak_count}")

# --- MAIN EXECUTION ---
if __name__ == "__main__":
    print("=== VPN LEAK TEST (Consolidated Report Version) ===")
    
    # 1. CAPTURE REAL IP
    print("[*] Detecting Baseline IP...")
    real_ip = get_real_ip_from_python()
    if real_ip == "Unknown":
        print("[!] Warning: Could not detect baseline IP.")
    else:
        print(f"    -> REAL ISP IP: {real_ip}")
        
    input("    Press ENTER to confirm VPN is currently OFF (to set baseline)...")

    # 2. LAUNCH CHROME
    chrome_options = Options()
    chrome_options.add_experimental_option("detach", True)
    chrome_options.add_experimental_option("prefs", {"dns_over_https.mode": "off"}) 
    chrome_options.add_argument("--disable-quic")
    
    driver = webdriver.Chrome(options=chrome_options)
    driver.set_page_load_timeout(5)

    # 3. VPN WAIT
    print(f"\n[*] BROWSER OPEN. Enable VPN within {VPN_SETUP_TIME} seconds.")
    try:
        for i in range(VPN_SETUP_TIME, 0, -1):
            sys.stdout.write(f"\r    Wait: {i}s... ")
            sys.stdout.flush()
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    
    print("\n\n[*] STARTING 5 ITERATION TEST CYCLES...")
    
    # --- STORAGE VARIABLES ---
    # Stores all IPs seen during the test to check for stability
    ip_history = []
    
    # Stores leak details. Structure: { "domain.com": [ {details}, {details} ] }
    master_leak_history = {} 

    try:
        for i in range(1, ITERATIONS + 1):
            print(f"\n=== ITERATION {i}/{ITERATIONS} ===")
            
            # Check IP
            current_browser_ip = get_browser_ip(driver)
            ip_history.append(current_browser_ip)
            
            is_ip_leak = (current_browser_ip == real_ip) and (real_ip != "Unknown")
            
            if is_ip_leak:
                print(f"[!!!] CRITICAL: IP LEAK! (Current: {current_browser_ip} == Real: {real_ip})")
            else:
                print(f"[+] IP Secure. Tunnel IP: {current_browser_ip}")

            print(f"[*] Testing {len(TARGET_DOMAINS)} domains...")
            
            for domain in TARGET_DOMAINS:
                clear_caches(driver)
                try:
                    driver.get(f"http://{domain}")
                except:
                    pass 
                
                time.sleep(1.0) 
                
                # Check Sysmon GLOBALLY (Any process)
                leak_xml = check_sysmon_globally(domain, lookback_seconds=4)
                
                if leak_xml:
                    # Parse XML
                    root = ET.fromstring(leak_xml)
                    pid = "Unknown"
                    image = "Unknown"
                    for data in root.findall(".//{http://schemas.microsoft.com/win/2004/08/events/event}Data"):
                         if data.get('Name') == 'ProcessId': pid = data.text
                         if data.get('Name') == 'Image': image = data.text

                    print(f"    [!] LEAK: {domain} -> Source: {image}")
                    
                    # --- STORE LEAK DETAILS ---
                    if domain not in master_leak_history:
                        master_leak_history[domain] = []
                    
                    master_leak_history[domain].append({
                        "iteration": i,
                        "time": datetime.datetime.now().strftime("%H:%M:%S"),
                        "source": image,
                        "pid": pid
                    })

                else:
                    print(f"    [✓] SAFE: {domain}")
            
            time.sleep(5)

    except KeyboardInterrupt:
        print("\n[!] Test Aborted by User.")
    finally:
        driver.quit()
        # --- GENERATE SINGLE REPORT AT THE END ---
        generate_final_txt_report(real_ip, ip_history, master_leak_history)