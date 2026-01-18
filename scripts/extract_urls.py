import sys
import re

def extract_urls(filename):
    with open(filename, "rb") as f:
        data = f.read()

    # Regex for URLs: http[s]:// followed by non-space chars
    url_pattern = re.compile(b"https?://[\w\-\._~:/?#[\]@!$&'()*+,;=]+")
    
    # Regex for "api." domains
    api_pattern = re.compile(b"api\.[\w\-\._]+")

    print(f"Scanning {filename} for URLs...")
    
    urls = url_pattern.findall(data)
    apis = api_pattern.findall(data)
    
    unique_urls = set()
    
    for u in urls:
        try:
            s = u.decode('utf-8')
            unique_urls.add(s)
        except: pass

    for a in apis:
        try:
            s = a.decode('utf-8')
            unique_urls.add(s)
        except: pass
        
    print(f"Found {len(unique_urls)} unique potential endpoints.")
    for u in sorted(unique_urls):
        print(u)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python extract_urls.py <file>")
        sys.exit(1)
    
    extract_urls(sys.argv[1])
