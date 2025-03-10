import nmap

def scan_network(target):
    scanner = nmap.PortScanner()
    print(f"Scanning {target}...")
    scanner.scan(target, '1-1024')
    
    for host in scanner.all_hosts():
        print(f"\nHost: {host} ({scanner[host].hostname()})")
        print("State:", scanner[host].state())
        for proto in scanner[host].all_protocols():
            print(f"Protocol: {proto}")
            ports = scanner[host][proto].keys()
            for port in ports:
                print(f"Port: {port}, State: {scanner[host][proto][port]['state']}")

if __name__ == "__main__":
    target_ip = input("Enter target IP: ")
    scan_network(target_ip)
