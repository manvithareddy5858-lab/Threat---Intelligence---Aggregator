import csv
import json

print("Threat Intelligence Aggregator Running...\n")

# Sample IOC data (simulating threat feeds)
ips = [
    "185.220.101.45",
    "103.21.244.0",
    "45.33.32.156",
]

domains = [
    "malicious-domain.com",
    "phishing-site.net",
    "badactor.ru",
]

urls = [
    "http://malicious-domain.com/login",
    "http://phishing-site.net/update",
]

hashes = [
    "44d88612fea8a8f36de82e1278abb02f",
    "098f6bcd4621d373cade4e832627b4f6",
]

# Write IP blocklist
with open("ip_blocklist.txt", "w") as f:
    for ip in ips:
        f.write(ip + "\n")

# Write domain blocklist
with open("domain_blocklist.txt", "w") as f:
    for domain in domains:
        f.write(domain + "\n")

# Write URL blocklist
with open("url_blocklist.txt", "w") as f:
    for url in urls:
        f.write(url + "\n")

# Write hash blocklist
with open("hash_blocklist.txt", "w") as f:
    for h in hashes:
        f.write(h + "\n")

# Create IOC database CSV
with open("IOC_Database.csv", "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Type", "Value"])

    for ip in ips:
        writer.writerow(["IP", ip])
    for d in domains:
        writer.writerow(["Domain", d])
    for u in urls:
        writer.writerow(["URL", u])
    for h in hashes:
        writer.writerow(["Hash", h])

# Create text report
with open("IOC_Correlation_Report.txt", "w") as f:
    f.write("Threat Intelligence Aggregation Report\n\n")
    f.write(f"Total IPs: {len(ips)}\n")
    f.write(f"Total Domains: {len(domains)}\n")
    f.write(f"Total URLs: {len(urls)}\n")
    f.write(f"Total Hashes: {len(hashes)}\n")

# JSON report
report = {
    "IPs": ips,
    "Domains": domains,
    "URLs": urls,
    "Hashes": hashes
}

with open("IOC_Correlation_Report.json", "w") as f:
    json.dump(report, f, indent=4)

print("Files generated successfully!")
