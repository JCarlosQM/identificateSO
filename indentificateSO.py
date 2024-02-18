import argparse
import ipaddress
import socket
import nmap
import subprocess
import re
from colorama import Fore, Style

# Definir colores
RED = Fore.RED
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
BLUE = Fore.BLUE
WHITE = Fore.WHITE
ORANGE = Fore.LIGHTYELLOW_EX
RESET = Style.RESET_ALL

def determinate_os():
    os_patterns = {
        "Linux": r"Linux",
        "Windows": r"Windows",
        "Mac": r"Mac OS X" 
    }
    return os_patterns

def ip_validated(ip, ports):
    nm = nmap.PortScanner()
    port_arg = ','.join(str(port) for port in ports)
    nm.scan(ip, arguments=f'-p {port_arg}')

    for hosts in nm.all_hosts():
        print(f"\n{ORANGE}Host: {hosts} {BLUE}({socket.gethostbyaddr(hosts)[0]})")
        for proto in nm[hosts].all_protocols():
            lport = nm[hosts][proto].keys()
            for port in lport:
                print(f"{ORANGE}port: {port}\tstate: {nm[hosts][proto][port]['state']}\t\tname: {nm[hosts][proto][port]['name']}{RESET}")
    
    try:
        result = subprocess.run(['nmap', '-O', ip], capture_output=True, text=True)
        os_detection_output = result.stdout
        os_patterns = determinate_os()
        for os_name, pattern in os_patterns.items():
            if re.search(pattern, os_detection_output, re.IGNORECASE):
                print(f"\n{RED}Para {ip} probablemente sea el SO {os_name}.")
                break
        else:
            print(f"\n{RED}El sistema operativo de {ip} no se pudo determinar.")
    except subprocess.CalledProcessError as e:
        print(f"{RED}Error al ejecutar nmap para la detección de sistema operativo: {e}")

def is_valid_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def parse_ports(ports_str):
    if ports_str:
        ports = []
        for port_range in ports_str.split(','):
            if '-' in port_range:
                start, end = map(int, port_range.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(port_range))
        return ports
    else:
        return None

def error(message):
    print(f"\n{RED}Error: {message}{RESET}\n")
    exit(1)

def main():
    parser = argparse.ArgumentParser(description=f'{RED}python3 identificateSO.py ip{RESET}', epilog=f'{BLUE}Autor: Juan Quevedo JC 2024{RESET}')
    parser.error = error
    parser.add_argument('ip', help='La dirección IP a identificar.')
    parser.add_argument('-PA', '--port-analysis', nargs='*', type=parse_ports, metavar='PORT', help='Realiza análisis en los puertos especificados.')
    args = parser.parse_args()

    if args.port_analysis is None:
        print(f"{YELLOW}\nNo se especificaron puertos para el análisis, se analizarán los primeros 1024 puertos.{RESET}")
        ports = range(1, 1025)
    else:
        if args.port_analysis:
            ports = args.port_analysis[0]
        else:
            error("Se esperaba al menos un puerto después de -PA.")
    
    if is_valid_ip(args.ip):
        ip_validated(args.ip, ports)
        print(f'{RESET}')
    else:
        error(f"{args.ip} no es una dirección IP válida.")

if __name__ == "__main__":
    main()
