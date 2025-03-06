import requests
import socket
import concurrent.futures
import dns.resolver
import time
from tabulate import tabulate

# Function to load wordlist efficiently
def load_wordlist(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return (line.strip() for line in file if line.strip())  # Generator for efficiency
    except Exception as e:
        print(f"[!] Error reading wordlist file: {e}")
        return []

# Function to fetch subdomains from crt.sh (Certificate Transparency logs)
def fetch_crtsh(domain):
    url = f'https://crt.sh/?q=%25.{domain}&output=json'
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return {entry['name_value'] for entry in response.json()}
    except Exception as e:
        print(f"[!] Error fetching from crt.sh: {e}")
    return set()

# Function to resolve subdomain to IP address using a specific DNS resolver
def resolve_subdomain(subdomain):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8"]  # Using Google's public DNS
    try:
        answer = resolver.resolve(subdomain, "A")
        return subdomain, answer[0].to_text()
    except:
        return subdomain, "Not resolved"

# Brute-force subdomain enumeration with optimized threading
def brute_force_subdomains(domain, wordlist_file):
    subdomains = set()
    with open(wordlist_file, "r", encoding="utf-8") as file:
        words = [line.strip() for line in file if line.strip()]  # Load wordlist into memory

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(resolve_subdomain, f"{sub}.{domain}"): sub for sub in words}
        for future in concurrent.futures.as_completed(futures):
            subdomain, ip = future.result()
            if ip:
                subdomains.add((subdomain, ip))
    return subdomains

if __name__ == "__main__":
    wordlist_file = "wordlist.txt"  # Specify the wordlist file
    
    while True:
        domain = input("Enter target domain : ")
        if domain.lower() == 'exit':
            break

        print(f"[+] Running brute-force subdomain enumeration for {domain}...")

        start_time = time.time()  # Start timer

        brute_force_subdomains_list = brute_force_subdomains(domain, wordlist_file)

        end_time = time.time()  # End timer
        total_time = end_time - start_time  # Calculate total time taken

        print(tabulate(brute_force_subdomains_list, headers=["Subdomain", "IP Address"], tablefmt="grid"))
        print(f"\n[+] Completed in {total_time:.2f} seconds")  # Print total time
