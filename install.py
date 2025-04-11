#!/usr/bin/env python3
"""
CBOM Detector Installer Script
This script installs the CBOM Detector tool and its dependencies.
"""

import os
import sys
import subprocess
import platform

def install_dependencies():
    """Install required Python packages"""
    print("Installing dependencies...")
    try:
        # List of required packages
        packages = [
            "colorama",
            "cryptography",
            "requests",
            "rich"
        ]
        
        # Install packages
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
        for package in packages:
            print(f"Installing {package}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        
        return True
    except Exception as e:
        print(f"Error installing dependencies: {str(e)}")
        return False

def install_package():
    """Install the CBOM Detector package"""
    print("Installing CBOM Detector...")
    try:
        # Install in development mode
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-e", "."])
        return True
    except Exception as e:
        print(f"Error installing package: {str(e)}")
        return False

def main():
    """Main installer function"""
    print("=" * 60)
    print("CBOM Detector - Installer")
    print("Cryptographic Bill of Materials Scanner and Quantum Risk Assessment Tool")
    print("=" * 60)
    
    # Check Python version
    python_version = sys.version_info
    if python_version.major < 3 or (python_version.major == 3 and python_version.minor < 6):
        print("Error: Python 3.6 or higher is required.")
        sys.exit(1)
    
    # Install dependencies
    if not install_dependencies():
        print("Failed to install dependencies. Please try again or install manually.")
        sys.exit(1)
    
    # Install package
    if not install_package():
        print("Failed to install CBOM Detector. Please try again or install manually.")
        sys.exit(1)
    
    print("\nInstallation completed successfully!")
    print("\nYou can now run CBOM Detector using the command:")
    print("  cbom-detector")
    print("\nThis will scan your system for cryptographic components and assess")
    print("their vulnerability to quantum computing attacks.")

if __name__ == "__main__":
    main()