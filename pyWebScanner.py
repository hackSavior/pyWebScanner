import nmap
from vulners import Vulners
import socket
import getpass
import colorama
from colorama import *
import sys
import time
colorama.init(autoreset=True)
toolName = (f"{Fore.RED}PyWebScanner")
print(f"""{Fore.RED}

                    ##########################################
                    $                                        $
                    $               {toolName}             $
                    $                                        $
                    $                   by                   $
                    $                                        $               
                    $               @hackSavior              $
                    $                                        $
                    ##########################################



""")


print(f"""{Fore.GREEN}      1. Web Port Scanner.
      2. Vulnerabilities Scanner.\n""")
def selections(): 
    selection = input(f"{Fore.LIGHTGREEN_EX}Select Option: ")
    if selection == "1":
        print("\n")
# Initialize the port scanner
        nmScan = nmap.PortScanner()

# Input validation function
        def validate_input(input_string):
            while True:
                targetHost = input(input_string)
                if not targetHost:
                    print("")
                    print(f"{Fore.LIGHTRED_EX}Please provide a hostname or IP address.\n")
                    continue
                print("")
                time.sleep(1)
                print(f"{Fore.LIGHTGREEN_EX}Scanning Started...")
                try:
                    socket.gethostbyname(targetHost)  # Attempt to resolve the host
                    nmScan.scan(targetHost, '20,21,22,23,25,53,80,110,115,119,123,143,153,161,443,465,587,993,995,3306,5432,8080')
                    break
                except socket.gaierror:
                    print(f"{Fore.LIGHTRED_EX}Invalid hostname or IP address. Please try again.\n")
                except KeyboardInterrupt:
                    print("\n\nExiting...")
                    sys.exit()

# Validate the input
        validate_input(f"{Fore.LIGHTGREEN_EX}[+] Enter Hostname or IP: ")
        print("\n")

# Run a loop to print all the found results about the ports
        for host in nmScan.all_hosts():
            print('Host : %s (%s)' % (host, nmScan[host].hostname()))
            print('State : %s' % nmScan[host].state())
            for proto in nmScan[host].all_protocols():
                print('----------')
                print('Protocol : %s' % proto)

                lport = nmScan[host][proto].keys()
                for port in lport:
                    print('port : %s\tstate : %s' % (port, nmScan[host][proto][port]['state']))
    elif selection == "2":
        print("\n")
        target = input(f"{Fore.LIGHTBLUE_EX}[++]Enter HostName or IP: ")
        def analyze_vulnerabilities(scan_results):
                while True:
                    if not target and apiKey:
                        print("Please Provide HostName and api_key..")
                        continue
                    try:
                        socket.gethostbyname(target)
                        vulnerabilities = []

                        vulners_api = Vulners(apiKey)

                        for host in scan_results.all_hosts():
                            for proto in scan_results[host].all_protocols():
                                ports = scan_results[host][proto].keys()
                                for port in ports:
                                    service = scan_results[host][proto][port]
                                    if 'product' in service and 'version' in service:
                    # Check for vulnerabilities based on service version using Vulners API
                                        vulnerabilities.extend(vulners_api.softwareVulnerabilities(service['product'], service['version']))

                        return vulnerabilities
                        
                    except socket.gaierror:
                        print("please enter valid hostName or IP..")
                        break
                    except KeyboardInterrupt:
                        sys.exit("Interrupted By User...")

# Example usage
        #target = input("Enter HostName or IP: ")  # Target IP address or hostname
        print(" ")
        apiKey = getpass.getpass(f"{Fore.LIGHTBLUE_EX}[++] Enter API key(vulners.com): ")

        nmScan = nmap.PortScanner()
        nmScan.scan(target, '20,21,22,23,25,53,80,110,115,119,123,143,153,161,443,465,587,993,995,3306,5432,8080')

        vulnerabilities = analyze_vulnerabilities(nmScan)

        if vulnerabilities:
            print(f"{Fore.LIGHTCYAN_EX}[+][+] Potential vulnerabilities:")
            for vuln in vulnerabilities:
                print(f"- {vuln}")
        else:
            print(f"{Fore.LIGHTRED_EX}[-] No vulnerabilities found [-]")



    else:
        print(f"{Fore.RED}Invalid Selection Try Again...\n")
        return selections()
colorama.deinit()
selections()