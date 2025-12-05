#!/usr/bin/env python3
"""
Setup script for Website Vulnerability Scanner
"""

import subprocess
import sys
import os

def print_banner():
    banner = """
 __          __  _                           
 \\ \\        / / | |                          
  \\ \\  /\\  / /__| |__    ___  ___ __ _ _ __  
   \\ \\/  \\/ / _ \\ '_ \\  / __|/ __/ _` | '_ \\ 
    \\  /\\  /  __/ |_) | \\__ \\ (_| (_| | | | |
     \\/  \\/ \\___|_.__/  |___/\\___\\__,_|_| |_|
                                             
    Website Vulnerability Scanner Setup
    Created by: G0$T×K9M
    """
    print(banner)

def check_python_version():
    """Check Python version"""
    print("[+] Checking Python version...")
    if sys.version_info < (3, 6):
        print("[-] Error: Python 3.6 or higher is required")
        print(f"[-] Current version: {sys.version}")
        return False
    print(f"[+] Python {sys.version} detected - OK")
    return True

def install_packages():
    """Install required packages"""
    print("\n[+] Installing required packages...")
    
    packages = [
        'requests>=2.28.0',
        'beautifulsoup4>=4.11.0',
        'colorama>=0.4.6'
    ]
    
    for package in packages:
        try:
            print(f"[+] Installing {package}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            print(f"[✓] Successfully installed {package}")
        except subprocess.CalledProcessError:
            print(f"[✗] Failed to install {package}")
            return False
    
    return True

def make_executable():
    """Make main script executable"""
    print("\n[+] Setting up permissions...")
    
    script_name = "web_scanner.py"
    if os.path.exists(script_name):
        try:
            os.chmod(script_name, 0o755)
            print(f"[✓] Made {script_name} executable")
        except:
            print(f"[!] Could not change permissions for {script_name}")
    else:
        print(f"[!] Warning: {script_name} not found in current directory")
    
    return True

def create_requirements_file():
    """Create requirements.txt file"""
    print("\n[+] Creating requirements.txt...")
    
    requirements = """requests>=2.28.0
beautifulsoup4>=4.11.0
colorama>=0.4.6
"""
    
    try:
        with open("requirements.txt", "w") as f:
            f.write(requirements)
        print("[✓] Created requirements.txt")
    except:
        print("[!] Could not create requirements.txt")
    
    return True

def main():
    """Main setup function"""
    print_banner()
    
    print("=" * 60)
    print("Installation Process Starting...")
    print("=" * 60)
    
    # Step 1: Check Python
    if not check_python_version():
        sys.exit(1)
    
    # Step 2: Install packages
    if not install_packages():
        print("[!] Some packages failed to install")
        print("[!] Try: pip3 install -r requirements.txt")
    
    # Step 3: Make executable
    make_executable()
    
    # Step 4: Create requirements file
    create_requirements_file()
    
    # Final message
    print("\n" + "=" * 60)
    print("SETUP COMPLETE!")
    print("=" * 60)
    print("\nUsage:")
    print("  python3 web_scanner.py <target_url>")
    print("  python3 web_scanner.py")
    print("\nExamples:")
    print("  python3 web_scanner.py http://testphp.vulnweb.com")
    print("  python3 web_scanner.py https://example.com")
    print("\nFor ethical use only!")
    print("=" * 60)

if __name__ == "__main__":
    main()