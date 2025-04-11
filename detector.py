import sys
import os
import json
import subprocess
import platform
import webbrowser
import logging
from datetime import datetime
import requests
from colorama import init, Fore, Style
import re
import ssl
import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, padding
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

# Initialize colorama for cross-platform colored terminal output
init()

# Initialize rich console
console = Console()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='cbom_detector.log'
)

logger = logging.getLogger('CBOM-Detector')

# Database of cryptographic algorithms and their risk levels
CRYPTO_RISK_DB = {
    # Asymmetric encryption algorithms
    "RSA": {
        "risk_level": "HIGH",
        "quantum_vulnerable": True,
        "reason": "Vulnerable to Shor's algorithm on quantum computers",
        "recommendation": "Migrate to quantum-resistant algorithms like CRYSTALS-Kyber"
    },
    "DSA": {
        "risk_level": "HIGH",
        "quantum_vulnerable": True,
        "reason": "Vulnerable to Shor's algorithm on quantum computers",
        "recommendation": "Migrate to quantum-resistant algorithms"
    },
    "ECC": {
        "risk_level": "HIGH",
        "quantum_vulnerable": True,
        "reason": "Vulnerable to Shor's algorithm on quantum computers",
        "recommendation": "Migrate to CRYSTALS-Dilithium or FALCON for signatures"
    },
    "DH": {
        "risk_level": "HIGH",
        "quantum_vulnerable": True,
        "reason": "Vulnerable to Shor's algorithm on quantum computers",
        "recommendation": "Migrate to quantum-resistant key exchange"
    },
    "ECDH": {
        "risk_level": "HIGH",
        "quantum_vulnerable": True,
        "reason": "Vulnerable to Shor's algorithm on quantum computers",
        "recommendation": "Migrate to CRYSTALS-Kyber"
    },
    "ECDSA": {
        "risk_level": "HIGH",
        "quantum_vulnerable": True,
        "reason": "Vulnerable to Shor's algorithm on quantum computers",
        "recommendation": "Migrate to CRYSTALS-Dilithium"
    },
    
    # Symmetric encryption algorithms
    "AES-128": {
        "risk_level": "MODERATE",
        "quantum_vulnerable": True,
        "reason": "Vulnerable to Grover's algorithm, effective security reduced to 64 bits",
        "recommendation": "Use AES-256 for long-term security"
    },
    "AES-192": {
        "risk_level": "LOW",
        "quantum_vulnerable": True,
        "reason": "Somewhat vulnerable to Grover's algorithm",
        "recommendation": "Consider AES-256 for long-term security"
    },
    "AES-256": {
        "risk_level": "LOW",
        "quantum_vulnerable": False,
        "reason": "Considered quantum-resistant against Grover's algorithm",
        "recommendation": "Continue using with proper key management"
    },
    "3DES": {
        "risk_level": "HIGH",
        "quantum_vulnerable": True,
        "reason": "Legacy algorithm with known vulnerabilities and quantum concerns",
        "recommendation": "Migrate to AES-256"
    },
    "DES": {
        "risk_level": "CRITICAL",
        "quantum_vulnerable": True,
        "reason": "Extremely vulnerable to classical attacks and quantum attacks",
        "recommendation": "Replace immediately with AES"
    },
    "RC4": {
        "risk_level": "CRITICAL",
        "quantum_vulnerable": True,
        "reason": "Cryptographically broken in classical computing",
        "recommendation": "Replace immediately with AES"
    },
    
    # Hash functions
    "MD5": {
        "risk_level": "CRITICAL",
        "quantum_vulnerable": True,
        "reason": "Cryptographically broken in classical computing",
        "recommendation": "Replace with SHA-256 or SHA-3"
    },
    "SHA-1": {
        "risk_level": "HIGH",
        "quantum_vulnerable": True,
        "reason": "Collisions found in classical computing",
        "recommendation": "Replace with SHA-256 or SHA-3"
    },
    "SHA-256": {
        "risk_level": "LOW",
        "quantum_vulnerable": True,
        "reason": "Grover's algorithm reduces security to 128 bits",
        "recommendation": "Suitable for most applications, consider SHA-384 or SHA-512 for long-term security"
    },
    "SHA-384": {
        "risk_level": "LOW",
        "quantum_vulnerable": False,
        "reason": "Considered resistant to quantum attacks",
        "recommendation": "Continue using"
    },
    "SHA-512": {
        "risk_level": "LOW", 
        "quantum_vulnerable": False,
        "reason": "Considered resistant to quantum attacks",
        "recommendation": "Continue using"
    },
    "SHA-3": {
        "risk_level": "LOW",
        "quantum_vulnerable": False,
        "reason": "Considered resistant to quantum attacks",
        "recommendation": "Recommended for new applications"
    },
    
    # Post-quantum algorithms
    "CRYSTALS-Kyber": {
        "risk_level": "LOW",
        "quantum_vulnerable": False,
        "reason": "NIST-selected post-quantum key encapsulation mechanism",
        "recommendation": "Suitable for replacing RSA/ECC for key exchange"
    },
    "CRYSTALS-Dilithium": {
        "risk_level": "LOW",
        "quantum_vulnerable": False,
        "reason": "NIST-selected post-quantum digital signature algorithm",
        "recommendation": "Suitable for replacing RSA/DSA/ECDSA for signatures"
    },
    "FALCON": {
        "risk_level": "LOW",
        "quantum_vulnerable": False,
        "reason": "NIST-selected post-quantum digital signature algorithm",
        "recommendation": "Alternative to CRYSTALS-Dilithium with different size/speed tradeoffs"
    },
    "SPHINCS+": {
        "risk_level": "LOW",
        "quantum_vulnerable": False,
        "reason": "NIST-selected post-quantum digital signature algorithm",
        "recommendation": "Stateless hash-based signature scheme, conservative choice"
    },
    
    # TLS protocol versions
    "TLS 1.0": {
        "risk_level": "HIGH",
        "quantum_vulnerable": True,
        "reason": "Deprecated protocol with known vulnerabilities",
        "recommendation": "Upgrade to TLS 1.2 or TLS 1.3"
    },
    "TLS 1.1": {
        "risk_level": "HIGH",
        "quantum_vulnerable": True,
        "reason": "Deprecated protocol with known vulnerabilities",
        "recommendation": "Upgrade to TLS 1.2 or TLS 1.3"
    },
    "TLS 1.2": {
        "risk_level": "MODERATE",
        "quantum_vulnerable": True,
        "reason": "Secure with proper configuration, but uses quantum-vulnerable algorithms",
        "recommendation": "Configure to use quantum-safe ciphersuites where possible or upgrade to TLS 1.3"
    },
    "TLS 1.3": {
        "risk_level": "LOW",
        "quantum_vulnerable": True,
        "reason": "Modern protocol but still relies on quantum-vulnerable algorithms for key exchange",
        "recommendation": "Best current option, but prepare for transition to quantum-resistant TLS"
    },
    "SSL 3.0": {
        "risk_level": "CRITICAL",
        "quantum_vulnerable": True,
        "reason": "Deprecated protocol with serious vulnerabilities (POODLE)",
        "recommendation": "Upgrade to TLS 1.2 or TLS 1.3 immediately"
    },
    "SSL 2.0": {
        "risk_level": "CRITICAL",
        "quantum_vulnerable": True,
        "reason": "Severely deprecated protocol with critical vulnerabilities",
        "recommendation": "Upgrade to TLS 1.2 or TLS 1.3 immediately"
    }
}

def get_system_info():
    """Gather basic system information"""
    info = {
        "os": platform.system(),
        "os_version": platform.version(),
        "platform": platform.platform(),
        "processor": platform.processor(),
        "python_version": sys.version,
        "time_of_scan": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    return info

def detect_installed_browsers():
    """Detect installed browsers on the system"""
    browsers = []
    system = platform.system()
    
    common_browsers = {
        "Windows": {
            "Chrome": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            "Chrome_x86": r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            "Firefox": r"C:\Program Files\Mozilla Firefox\firefox.exe",
            "Firefox_x86": r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe",
            "Edge": r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            "Edge_new": r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
            "Opera": r"C:\Program Files\Opera\launcher.exe",
            "Opera_x86": r"C:\Program Files (x86)\Opera\launcher.exe",
            "Brave": r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
        },
        "Darwin": {  # macOS
            "Chrome": "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "Firefox": "/Applications/Firefox.app/Contents/MacOS/firefox",
            "Safari": "/Applications/Safari.app/Contents/MacOS/Safari",
            "Edge": "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            "Opera": "/Applications/Opera.app/Contents/MacOS/Opera",
            "Brave": "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
        },
        "Linux": {
            "Chrome": "google-chrome",
            "Chromium": "chromium-browser",
            "Firefox": "firefox",
            "Opera": "opera",
            "Brave": "brave-browser",
        }
    }
    
    if system in common_browsers:
        for browser_name, browser_path in common_browsers[system].items():
            try:
                if system == "Linux":
                    # For Linux, check if the browser is in PATH
                    try:
                        subprocess.check_output(["which", browser_path])
                        browsers.append({"name": browser_name, "path": browser_path})
                    except subprocess.CalledProcessError:
                        continue
                else:
                    # For Windows and macOS, check if the file exists
                    if os.path.exists(browser_path):
                        browsers.append({"name": browser_name, "path": browser_path})
            except Exception as e:
                logger.error(f"Error detecting browser {browser_name}: {str(e)}")
    
    return browsers

def check_browser_security_features(browser_info):
    """Analyze browser's security features and cryptographic capabilities"""
    browser_name = browser_info["name"]
    security_features = {
        "name": browser_name,
        "detected_cryptography": []
    }
    
    # Common cryptographic features in modern browsers
    if browser_name in ["Chrome", "Chrome_x86", "Chromium"]:
        security_features["detected_cryptography"] = [
            {"type": "Key Exchange", "algorithm": "ECDHE", "risk_level": CRYPTO_RISK_DB["ECDH"]["risk_level"]},
            {"type": "Digital Signature", "algorithm": "RSA", "risk_level": CRYPTO_RISK_DB["RSA"]["risk_level"]},
            {"type": "Digital Signature", "algorithm": "ECDSA", "risk_level": CRYPTO_RISK_DB["ECDSA"]["risk_level"]},
            {"type": "Symmetric Encryption", "algorithm": "AES-256", "risk_level": CRYPTO_RISK_DB["AES-256"]["risk_level"]},
            {"type": "Hashing", "algorithm": "SHA-256", "risk_level": CRYPTO_RISK_DB["SHA-256"]["risk_level"]},
            {"type": "Protocol", "algorithm": "TLS 1.3", "risk_level": CRYPTO_RISK_DB["TLS 1.3"]["risk_level"]}
        ]
    elif browser_name in ["Firefox", "Firefox_x86"]:
        security_features["detected_cryptography"] = [
            {"type": "Key Exchange", "algorithm": "ECDHE", "risk_level": CRYPTO_RISK_DB["ECDH"]["risk_level"]},
            {"type": "Digital Signature", "algorithm": "RSA", "risk_level": CRYPTO_RISK_DB["RSA"]["risk_level"]},
            {"type": "Digital Signature", "algorithm": "ECDSA", "risk_level": CRYPTO_RISK_DB["ECDSA"]["risk_level"]},
            {"type": "Symmetric Encryption", "algorithm": "AES-256", "risk_level": CRYPTO_RISK_DB["AES-256"]["risk_level"]},
            {"type": "Hashing", "algorithm": "SHA-256", "risk_level": CRYPTO_RISK_DB["SHA-256"]["risk_level"]},
            {"type": "Protocol", "algorithm": "TLS 1.3", "risk_level": CRYPTO_RISK_DB["TLS 1.3"]["risk_level"]}
        ]
    elif browser_name in ["Edge", "Edge_new"]:
        security_features["detected_cryptography"] = [
            {"type": "Key Exchange", "algorithm": "ECDHE", "risk_level": CRYPTO_RISK_DB["ECDH"]["risk_level"]},
            {"type": "Digital Signature", "algorithm": "RSA", "risk_level": CRYPTO_RISK_DB["RSA"]["risk_level"]},
            {"type": "Digital Signature", "algorithm": "ECDSA", "risk_level": CRYPTO_RISK_DB["ECDSA"]["risk_level"]},
            {"type": "Symmetric Encryption", "algorithm": "AES-256", "risk_level": CRYPTO_RISK_DB["AES-256"]["risk_level"]},
            {"type": "Hashing", "algorithm": "SHA-256", "risk_level": CRYPTO_RISK_DB["SHA-256"]["risk_level"]},
            {"type": "Protocol", "algorithm": "TLS 1.3", "risk_level": CRYPTO_RISK_DB["TLS 1.3"]["risk_level"]}
        ]
    elif browser_name == "Safari":
        security_features["detected_cryptography"] = [
            {"type": "Key Exchange", "algorithm": "ECDHE", "risk_level": CRYPTO_RISK_DB["ECDH"]["risk_level"]},
            {"type": "Digital Signature", "algorithm": "RSA", "risk_level": CRYPTO_RISK_DB["RSA"]["risk_level"]},
            {"type": "Digital Signature", "algorithm": "ECDSA", "risk_level": CRYPTO_RISK_DB["ECDSA"]["risk_level"]},
            {"type": "Symmetric Encryption", "algorithm": "AES-256", "risk_level": CRYPTO_RISK_DB["AES-256"]["risk_level"]},
            {"type": "Hashing", "algorithm": "SHA-256", "risk_level": CRYPTO_RISK_DB["SHA-256"]["risk_level"]},
            {"type": "Protocol", "algorithm": "TLS 1.3", "risk_level": CRYPTO_RISK_DB["TLS 1.3"]["risk_level"]}
        ]
    elif browser_name in ["Opera", "Opera_x86"]:
        security_features["detected_cryptography"] = [
            {"type": "Key Exchange", "algorithm": "ECDHE", "risk_level": CRYPTO_RISK_DB["ECDH"]["risk_level"]},
            {"type": "Digital Signature", "algorithm": "RSA", "risk_level": CRYPTO_RISK_DB["RSA"]["risk_level"]},
            {"type": "Digital Signature", "algorithm": "ECDSA", "risk_level": CRYPTO_RISK_DB["ECDSA"]["risk_level"]},
            {"type": "Symmetric Encryption", "algorithm": "AES-256", "risk_level": CRYPTO_RISK_DB["AES-256"]["risk_level"]},
            {"type": "Hashing", "algorithm": "SHA-256", "risk_level": CRYPTO_RISK_DB["SHA-256"]["risk_level"]},
            {"type": "Protocol", "algorithm": "TLS 1.3", "risk_level": CRYPTO_RISK_DB["TLS 1.3"]["risk_level"]}
        ]
    elif browser_name in ["Brave", "Brave Browser"]:
        security_features["detected_cryptography"] = [
            {"type": "Key Exchange", "algorithm": "ECDHE", "risk_level": CRYPTO_RISK_DB["ECDH"]["risk_level"]},
            {"type": "Digital Signature", "algorithm": "RSA", "risk_level": CRYPTO_RISK_DB["RSA"]["risk_level"]},
            {"type": "Digital Signature", "algorithm": "ECDSA", "risk_level": CRYPTO_RISK_DB["ECDSA"]["risk_level"]},
            {"type": "Symmetric Encryption", "algorithm": "AES-256", "risk_level": CRYPTO_RISK_DB["AES-256"]["risk_level"]},
            {"type": "Hashing", "algorithm": "SHA-256", "risk_level": CRYPTO_RISK_DB["SHA-256"]["risk_level"]},
            {"type": "Protocol", "algorithm": "TLS 1.3", "risk_level": CRYPTO_RISK_DB["TLS 1.3"]["risk_level"]}
        ]
    
    return security_features

def detect_system_cryptography():
    """Detect cryptographic libraries and modules at the system level"""
    system_crypto = []
    
    # Check installed Python cryptographic libraries
    try:
        import importlib
        
        crypto_libs = [
            "cryptography", "pycrypto", "pyca", "pynacl", "m2crypto", 
            "pyopenssl", "pycryptodome", "hashlib"
        ]
        
        for lib in crypto_libs:
            try:
                importlib.import_module(lib)
                if lib == "cryptography":
                    system_crypto.append({
                        "name": "Python cryptography",
                        "type": "Library",
                        "algorithms": [
                            {"type": "Asymmetric", "algorithm": "RSA", "risk_level": CRYPTO_RISK_DB["RSA"]["risk_level"]},
                            {"type": "Asymmetric", "algorithm": "ECC", "risk_level": CRYPTO_RISK_DB["ECC"]["risk_level"]},
                            {"type": "Symmetric", "algorithm": "AES-256", "risk_level": CRYPTO_RISK_DB["AES-256"]["risk_level"]},
                            {"type": "Hashing", "algorithm": "SHA-256", "risk_level": CRYPTO_RISK_DB["SHA-256"]["risk_level"]}
                        ]
                    })
                elif lib == "pycrypto" or lib == "pycryptodome":
                    system_crypto.append({
                        "name": lib,
                        "type": "Library",
                        "algorithms": [
                            {"type": "Asymmetric", "algorithm": "RSA", "risk_level": CRYPTO_RISK_DB["RSA"]["risk_level"]},
                            {"type": "Asymmetric", "algorithm": "DSA", "risk_level": CRYPTO_RISK_DB["DSA"]["risk_level"]},
                            {"type": "Symmetric", "algorithm": "AES-256", "risk_level": CRYPTO_RISK_DB["AES-256"]["risk_level"]},
                            {"type": "Symmetric", "algorithm": "3DES", "risk_level": CRYPTO_RISK_DB["3DES"]["risk_level"]},
                            {"type": "Hashing", "algorithm": "SHA-256", "risk_level": CRYPTO_RISK_DB["SHA-256"]["risk_level"]}
                        ]
                    })
                elif lib == "hashlib":
                    system_crypto.append({
                        "name": "Python hashlib",
                        "type": "Library",
                        "algorithms": [
                            {"type": "Hashing", "algorithm": "MD5", "risk_level": CRYPTO_RISK_DB["MD5"]["risk_level"]},
                            {"type": "Hashing", "algorithm": "SHA-1", "risk_level": CRYPTO_RISK_DB["SHA-1"]["risk_level"]},
                            {"type": "Hashing", "algorithm": "SHA-256", "risk_level": CRYPTO_RISK_DB["SHA-256"]["risk_level"]},
                            {"type": "Hashing", "algorithm": "SHA-512", "risk_level": CRYPTO_RISK_DB["SHA-512"]["risk_level"]}
                        ]
                    })
                # Add other libraries as needed
            except ImportError:
                pass
    except Exception as e:
        logger.error(f"Error detecting Python crypto libraries: {str(e)}")
    
    # Check OpenSSL version and capabilities
    try:
        openssl_version = ssl.OPENSSL_VERSION
        system_crypto.append({
            "name": openssl_version,
            "type": "System Library",
            "algorithms": [
                {"type": "Key Exchange", "algorithm": "RSA", "risk_level": CRYPTO_RISK_DB["RSA"]["risk_level"]},
                {"type": "Key Exchange", "algorithm": "DH", "risk_level": CRYPTO_RISK_DB["DH"]["risk_level"]},
                {"type": "Key Exchange", "algorithm": "ECDH", "risk_level": CRYPTO_RISK_DB["ECDH"]["risk_level"]},
                {"type": "Digital Signature", "algorithm": "RSA", "risk_level": CRYPTO_RISK_DB["RSA"]["risk_level"]},
                {"type": "Digital Signature", "algorithm": "DSA", "risk_level": CRYPTO_RISK_DB["DSA"]["risk_level"]},
                {"type": "Digital Signature", "algorithm": "ECDSA", "risk_level": CRYPTO_RISK_DB["ECDSA"]["risk_level"]},
                {"type": "Symmetric Encryption", "algorithm": "AES-256", "risk_level": CRYPTO_RISK_DB["AES-256"]["risk_level"]},
                {"type": "Symmetric Encryption", "algorithm": "3DES", "risk_level": CRYPTO_RISK_DB["3DES"]["risk_level"]},
                {"type": "Hashing", "algorithm": "SHA-256", "risk_level": CRYPTO_RISK_DB["SHA-256"]["risk_level"]},
                {"type": "Hashing", "algorithm": "SHA-512", "risk_level": CRYPTO_RISK_DB["SHA-512"]["risk_level"]}
            ]
        })
    except Exception as e:
        logger.error(f"Error detecting OpenSSL: {str(e)}")
    
    # Detect TLS configuration
    try:
        context = ssl.create_default_context()
        protocols = []
        if hasattr(ssl, 'PROTOCOL_TLSv1_3') and context.maximum_version >= ssl.TLSVersion.TLSv1_3:
            protocols.append({"protocol": "TLS 1.3", "risk_level": CRYPTO_RISK_DB["TLS 1.3"]["risk_level"]})
        if hasattr(ssl, 'PROTOCOL_TLSv1_2') and context.maximum_version >= ssl.TLSVersion.TLSv1_2:
            protocols.append({"protocol": "TLS 1.2", "risk_level": CRYPTO_RISK_DB["TLS 1.2"]["risk_level"]})
        system_crypto.append({
            "name": "TLS Configuration",
            "type": "Protocol",
            "protocols": protocols
        })
    except Exception as e:
        logger.error(f"Error detecting TLS configuration: {str(e)}")
    
    return system_crypto

def check_usb_devices():
    """Check USB devices for potential cryptographic hardware"""
    crypto_devices = []
    system = platform.system()
    
    try:
        if system == "Windows":
            # For Windows, use powershell or wmic
            cmd = "wmic path Win32_USBControllerDevice get Dependent /value"
            output = subprocess.check_output(cmd, shell=True).decode()
            
            # Look for potential crypto devices
            if "YubiKey" in output or "Security Key" in output:
                crypto_devices.append({
                    "name": "YubiKey or Security Key",
                    "type": "Hardware Token",
                    "algorithms": [
                        {"type": "Digital Signature", "algorithm": "RSA", "risk_level": CRYPTO_RISK_DB["RSA"]["risk_level"]},
                        {"type": "Digital Signature", "algorithm": "ECDSA", "risk_level": CRYPTO_RISK_DB["ECDSA"]["risk_level"]},
                        {"type": "Key Storage", "algorithm": "Various", "risk_level": "VARIES"}
                    ]
                })
        
        elif system == "Darwin":  # macOS
            cmd = "system_profiler SPUSBDataType"
            output = subprocess.check_output(cmd, shell=True).decode()
            
            if "YubiKey" in output or "Security Key" in output:
                crypto_devices.append({
                    "name": "YubiKey or Security Key",
                    "type": "Hardware Token",
                    "algorithms": [
                        {"type": "Digital Signature", "algorithm": "RSA", "risk_level": CRYPTO_RISK_DB["RSA"]["risk_level"]},
                        {"type": "Digital Signature", "algorithm": "ECDSA", "risk_level": CRYPTO_RISK_DB["ECDSA"]["risk_level"]},
                        {"type": "Key Storage", "algorithm": "Various", "risk_level": "VARIES"}
                    ]
                })
        
        elif system == "Linux":
            cmd = "lsusb"
            output = subprocess.check_output(cmd, shell=True).decode()
            
            if "Yubico" in output or "Security Key" in output:
                crypto_devices.append({
                    "name": "YubiKey or Security Key",
                    "type": "Hardware Token",
                    "algorithms": [
                        {"type": "Digital Signature", "algorithm": "RSA", "risk_level": CRYPTO_RISK_DB["RSA"]["risk_level"]},
                        {"type": "Digital Signature", "algorithm": "ECDSA", "risk_level": CRYPTO_RISK_DB["ECDSA"]["risk_level"]},
                        {"type": "Key Storage", "algorithm": "Various", "risk_level": "VARIES"}
                    ]
                })
    except Exception as e:
        logger.error(f"Error checking USB devices: {str(e)}")
    
    # Add generic placeholder for demo purposes if nothing detected
    if not crypto_devices:
        crypto_devices.append({
            "name": "No cryptographic hardware detected",
            "type": "N/A",
            "algorithms": []
        })
    
    return crypto_devices

def scan_for_vulnerable_crypto():
    """Main scanning function to detect cryptographic components and assess risks"""
    results = {
        "system_info": get_system_info(),
        "browsers": [],
        "system_cryptography": [],
        "hardware_tokens": [],
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "risk_summary": {
            "critical": 0,
            "high": 0,
            "moderate": 0,
            "low": 0,
            "quantum_vulnerable_count": 0
        }
    }
    
    # Detect browsers
    console.print("\n[bold blue]Scanning browsers...[/bold blue]")
    browsers = detect_installed_browsers()
    
    # Check browser security features
    for browser in browsers:
        console.print(f"  [blue]Analyzing {browser['name']}...[/blue]")
        security_features = check_browser_security_features(browser)
        results["browsers"].append(security_features)
    
    # Detect system-level cryptography
    console.print("\n[bold blue]Scanning system cryptography...[/bold blue]")
    results["system_cryptography"] = detect_system_cryptography()
    
    # Check for hardware tokens and USB security devices
    console.print("\n[bold blue]Checking for cryptographic hardware...[/bold blue]")
    results["hardware_tokens"] = check_usb_devices()
    
    # Calculate risk summary
    console.print("\n[bold blue]Generating risk assessment...[/bold blue]")
    quantum_vulnerable = []
    
    # Process browsers
    for browser in results["browsers"]:
        for crypto in browser["detected_cryptography"]:
            if crypto["risk_level"] == "CRITICAL":
                results["risk_summary"]["critical"] += 1
            elif crypto["risk_level"] == "HIGH":
                results["risk_summary"]["high"] += 1
            elif crypto["risk_level"] == "MODERATE":
                results["risk_summary"]["moderate"] += 1
            elif crypto["risk_level"] == "LOW":
                results["risk_summary"]["low"] += 1
            
            algo = crypto["algorithm"]
            if algo in CRYPTO_RISK_DB and CRYPTO_RISK_DB[algo]["quantum_vulnerable"]:
                results["risk_summary"]["quantum_vulnerable_count"] += 1
                if algo not in quantum_vulnerable:
                    quantum_vulnerable.append(algo)
    
    # Process system cryptography
    for item in results["system_cryptography"]:
        if "algorithms" in item:
            for crypto in item["algorithms"]:
                if "risk_level" in crypto:
                    if crypto["risk_level"] == "CRITICAL":
                        results["risk_summary"]["critical"] += 1
                    elif crypto["risk_level"] == "HIGH":
                        results["risk_summary"]["high"] += 1
                    elif crypto["risk_level"] == "MODERATE":
                        results["risk_summary"]["moderate"] += 1
                    elif crypto["risk_level"] == "LOW":
                        results["risk_summary"]["low"] += 1
                
                algo = crypto["algorithm"]
                if algo in CRYPTO_RISK_DB and CRYPTO_RISK_DB[algo]["quantum_vulnerable"]:
                    results["risk_summary"]["quantum_vulnerable_count"] += 1
                    if algo not in quantum_vulnerable:
                        quantum_vulnerable.append(algo)
    
    # Process hardware tokens
    for device in results["hardware_tokens"]:
        if "algorithms" in device:
            for crypto in device["algorithms"]:
                if "risk_level" in crypto and crypto["risk_level"] != "VARIES":
                    if crypto["risk_level"] == "CRITICAL":
                        results["risk_summary"]["critical"] += 1
                    elif crypto["risk_level"] == "HIGH":
                        results["risk_summary"]["high"] += 1
                    elif crypto["risk_level"] == "MODERATE":
                        results["risk_summary"]["moderate"] += 1
                    elif crypto["risk_level"] == "LOW":
                        results["risk_summary"]["low"] += 1
                
                algo = crypto["algorithm"]
                if algo in CRYPTO_RISK_DB and CRYPTO_RISK_DB[algo]["quantum_vulnerable"]:
                    results["risk_summary"]["quantum_vulnerable_count"] += 1
                    if algo not in quantum_vulnerable:
                        quantum_vulnerable.append(algo)
    
    # Add quantum vulnerability list to results
    results["quantum_vulnerable_algorithms"] = quantum_vulnerable
    
    return results

def generate_report(scan_results):
    """Generate a comprehensive report from scan results"""
    console.print("\n[bold green]Generating CBOM Report...[/bold green]")
    
    # Create system info section
    console.print(Panel.fit(
        f"[bold]System Information[/bold]\n"
        f"OS: {scan_results['system_info']['os']} {scan_results['system_info']['os_version']}\n"
        f"Platform: {scan_results['system_info']['platform']}\n"
        f"Python Version: {scan_results['system_info']['python_version'].split()[0]}\n"
        f"Scan Time: {scan_results['scan_time']}",
        title="[white]System Details[/white]",
        border_style="blue"
    ))
    
    # Create risk summary table
    risk_table = Table(title="Risk Summary")
    risk_table.add_column("Risk Level", style="white")
    risk_table.add_column("Count", style="white")
    
    risk_table.add_row("CRITICAL", f"[bold red]{scan_results['risk_summary']['critical']}[/bold red]")
    risk_table.add_row("HIGH", f"[bold yellow]{scan_results['risk_summary']['high']}[/bold yellow]")
    risk_table.add_row("MODERATE", f"[bold blue]{scan_results['risk_summary']['moderate']}[/bold blue]")
    risk_table.add_row("LOW", f"[bold green]{scan_results['risk_summary']['low']}[/bold green]")
    risk_table.add_row("Quantum Vulnerable", f"[bold magenta]{scan_results['risk_summary']['quantum_vulnerable_count']}[/bold magenta]")
    
    console.print(risk_table)
    
    # Display quantum vulnerable algorithms
    if scan_results.get('quantum_vulnerable_algorithms'):
        console.print(Panel.fit(
            ", ".join(scan_results['quantum_vulnerable_algorithms']),
            title="[white]Quantum Vulnerable Algorithms[/white]",
            border_style="magenta"
        ))
    
    # Browser cryptography table
    if scan_results['browsers']:
        browser_table = Table(title="Browser Cryptography")
        browser_table.add_column("Browser", style="white")
        browser_table.add_column("Algorithm", style="white")
        browser_table.add_column("Type", style="white")
        browser_table.add_column("Risk Level", style="white")
        
        for browser in scan_results['browsers']:
            for crypto in browser['detected_cryptography']:
                risk_color = "green"
                if crypto['risk_level'] == "CRITICAL":
                    risk_color = "red"
                elif crypto['risk_level'] == "HIGH":
                    risk_color = "yellow"
                elif crypto['risk_level'] == "MODERATE":
                    risk_color = "blue"
                
                browser_table.add_row(
                    browser['name'],
                    crypto['algorithm'],
                    crypto['type'],
                    f"[{risk_color}]{crypto['risk_level']}[/{risk_color}]"
                )
        
        console.print(browser_table)
    
    # System cryptography table
    sys_crypto_table = Table(title="System Cryptography")
    sys_crypto_table.add_column("Component", style="white")
    sys_crypto_table.add_column("Type", style="white")
    sys_crypto_table.add_column("Algorithm", style="white")
    sys_crypto_table.add_column("Risk Level", style="white")
    
    for item in scan_results['system_cryptography']:
        if 'algorithms' in item:
            for algo in item['algorithms']:
                risk_color = "green"
                if algo.get('risk_level') == "CRITICAL":
                    risk_color = "red"
                elif algo.get('risk_level') == "HIGH":
                    risk_color = "yellow"
                elif algo.get('risk_level') == "MODERATE":
                    risk_color = "blue"
                
                sys_crypto_table.add_row(
                    item['name'],
                    algo['type'],
                    algo['algorithm'],
                    f"[{risk_color}]{algo.get('risk_level', 'UNKNOWN')}[/{risk_color}]"
                )
    
    console.print(sys_crypto_table)
    
    # Hardware tokens/devices table
    if any(device['algorithms'] for device in scan_results['hardware_tokens']):
        hw_table = Table(title="Cryptographic Hardware")
        hw_table.add_column("Device", style="white")
        hw_table.add_column("Type", style="white")
        hw_table.add_column("Algorithm", style="white")
        hw_table.add_column("Risk Level", style="white")
        
        for device in scan_results['hardware_tokens']:
            if device['algorithms']:
                for algo in device['algorithms']:
                    risk_color = "green"
                    if algo.get('risk_level') == "CRITICAL":
                        risk_color = "red"
                    elif algo.get('risk_level') == "HIGH":
                        risk_color = "yellow"
                    elif algo.get('risk_level') == "MODERATE":
                        risk_color = "blue"
                    
                    hw_table.add_row(
                        device['name'],
                        device['type'],
                        algo['algorithm'],
                        f"[{risk_color}]{algo.get('risk_level', 'UNKNOWN')}[/{risk_color}]"
                    )
        
        console.print(hw_table)
    
    # Generate mitigation recommendations
    recommendations = []
    critical_algos = []
    high_risk_algos = []
    
    # Process browsers
    for browser in scan_results['browsers']:
        for crypto in browser['detected_cryptography']:
            if crypto['risk_level'] == "CRITICAL" and crypto['algorithm'] not in critical_algos:
                critical_algos.append(crypto['algorithm'])
            elif crypto['risk_level'] == "HIGH" and crypto['algorithm'] not in high_risk_algos:
                high_risk_algos.append(crypto['algorithm'])
    
    # Process system cryptography
    for item in scan_results['system_cryptography']:
        if 'algorithms' in item:
            for crypto in item['algorithms']:
                if crypto.get('risk_level') == "CRITICAL" and crypto['algorithm'] not in critical_algos:
                    critical_algos.append(crypto['algorithm'])
                elif crypto.get('risk_level') == "HIGH" and crypto['algorithm'] not in high_risk_algos:
                    high_risk_algos.append(crypto['algorithm'])
    
    # Generate recommendations
    for algo in critical_algos:
        if algo in CRYPTO_RISK_DB:
            recommendations.append(f"[red]CRITICAL[/red]: Replace {algo} - {CRYPTO_RISK_DB[algo]['recommendation']}")
    
    for algo in high_risk_algos:
        if algo in CRYPTO_RISK_DB:
            recommendations.append(f"[yellow]HIGH[/yellow]: Mitigate {algo} - {CRYPTO_RISK_DB[algo]['recommendation']}")
    
    if recommendations:
        console.print(Panel.fit(
            "\n".join(recommendations),
            title="[white]Recommended Mitigations[/white]",
            border_style="green"
        ))
    
    # Export report
    report_filename = f"cbom_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_filename, 'w') as f:
        json.dump(scan_results, f, indent=2)
    
    console.print(f"\n[green]Report saved to {report_filename}[/green]")
    
    # Calculate overall quantum readiness score (0-100)
    total_components = (scan_results['risk_summary']['critical'] + 
                         scan_results['risk_summary']['high'] + 
                         scan_results['risk_summary']['moderate'] + 
                         scan_results['risk_summary']['low'])
    
    if total_components > 0:
        quantum_vulnerable_percentage = (scan_results['risk_summary']['quantum_vulnerable_count'] / total_components) * 100
        quantum_readiness_score = max(0, 100 - quantum_vulnerable_percentage)
    else:
        quantum_readiness_score = 100
    
    console.print(Panel.fit(
        f"[bold]Quantum Readiness Score: {quantum_readiness_score:.1f}/100[/bold]",
        title="[white]Readiness Assessment[/white]",
        border_style="cyan"
    ))
    
    return report_filename

def main():
    """Main function to run the CBOM Detector"""
    console.print(Panel.fit(
        "[bold]CBOM Detector v1.0[/bold]\n"
        "Cryptographic Bill of Materials Scanner and Quantum Risk Assessment Tool",
        title="[white]Welcome[/white]",
        border_style="green"
    ))
    
    console.print("\n[bold blue]Starting system scan...[/bold blue]")
    results = scan_for_vulnerable_crypto()
    
    report_file = generate_report(results)
    
    console.print("\n[bold green]Scan complete![/bold green]")
    console.print(f"[green]Report saved to: {report_file}[/green]")
    
    # Generate HTML report for better visualization
    try:
        with open(report_file, 'r') as f:
            data = json.load(f)
        
        html_report = f"cbom_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(html_report, 'w') as f:
            f.write(f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>CBOM Detector Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    h1, h2 {{ color: #333; }}
                    .summary {{ background-color: #f5f5f5; padding: 15px; border-radius: 5px; }}
                    .critical {{ color: red; font-weight: bold; }}
                    .high {{ color: orange; font-weight: bold; }}
                    .moderate {{ color: blue; }}
                    .low {{ color: green; }}
                    table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
                    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                    th {{ background-color: #f2f2f2; }}
                    tr:nth-child(even) {{ background-color: #f9f9f9; }}
                </style>
            </head>
            <body>
                <h1>CBOM Detector Report</h1>
                <div class="summary">
                    <h2>System Information</h2>
                    <p>OS: {data['system_info']['os']} {data['system_info']['os_version']}</p>
                    <p>Platform: {data['system_info']['platform']}</p>
                    <p>Scan Time: {data['scan_time']}</p>
                    
                    <h2>Risk Summary</h2>
                    <p>Critical Issues: <span class="critical">{data['risk_summary']['critical']}</span></p>
                    <p>High Risk Issues: <span class="high">{data['risk_summary']['high']}</span></p>
                    <p>Moderate Risk Issues: <span class="moderate">{data['risk_summary']['moderate']}</span></p>
                    <p>Low Risk Issues: <span class="low">{data['risk_summary']['low']}</span></p>
                    <p>Quantum Vulnerable Components: {data['risk_summary']['quantum_vulnerable_count']}</p>
                </div>
            """)
            
            # Add browser section
            if data['browsers']:
                f.write("""
                <h2>Browser Cryptography</h2>
                <table>
                    <tr>
                        <th>Browser</th>
                        <th>Algorithm</th>
                        <th>Type</th>
                        <th>Risk Level</th>
                    </tr>
                """)
                
                for browser in data['browsers']:
                    for crypto in browser['detected_cryptography']:
                        risk_class = "low"
                        if crypto['risk_level'] == "CRITICAL":
                            risk_class = "critical"
                        elif crypto['risk_level'] == "HIGH":
                            risk_class = "high"
                        elif crypto['risk_level'] == "MODERATE":
                            risk_class = "moderate"
                        
                        f.write(f"""
                        <tr>
                            <td>{browser['name']}</td>
                            <td>{crypto['algorithm']}</td>
                            <td>{crypto['type']}</td>
                            <td class="{risk_class}">{crypto['risk_level']}</td>
                        </tr>
                        """)
                
                f.write("</table>")
            
            # Add system cryptography section
            f.write("""
            <h2>System Cryptography</h2>
            <table>
                <tr>
                    <th>Component</th>
                    <th>Type</th>
                    <th>Algorithm</th>
                    <th>Risk Level</th>
                </tr>
            """)
            
            for item in data['system_cryptography']:
                if 'algorithms' in item:
                    for algo in item['algorithms']:
                        risk_class = "low"
                        risk_level = algo.get('risk_level', 'UNKNOWN')
                        
                        if risk_level == "CRITICAL":
                            risk_class = "critical"
                        elif risk_level == "HIGH":
                            risk_class = "high"
                        elif risk_level == "MODERATE":
                            risk_class = "moderate"
                        
                        f.write(f"""
                        <tr>
                            <td>{item['name']}</td>
                            <td>{algo['type']}</td>
                            <td>{algo['algorithm']}</td>
                            <td class="{risk_class}">{risk_level}</td>
                        </tr>
                        """)
            
            f.write("</table>")
            
            # Add recommendations
            f.write("""
            <h2>Recommendations</h2>
            <ul>
            """)
            
            for algo_name, algo_data in CRYPTO_RISK_DB.items():
                if algo_name in data.get('quantum_vulnerable_algorithms', []):
                    risk_class = "low"
                    if algo_data['risk_level'] == "CRITICAL":
                        risk_class = "critical"
                    elif algo_data['risk_level'] == "HIGH":
                        risk_class = "high"
                    elif algo_data['risk_level'] == "MODERATE":
                        risk_class = "moderate"
                    
                    f.write(f"""
                    <li class="{risk_class}">
                        <strong>{algo_name}:</strong> {algo_data['reason']} - {algo_data['recommendation']}
                    </li>
                    """)
            
            f.write("""
            </ul>
            </body>
            </html>
            """)
            
        console.print(f"[green]HTML Report generated: {html_report}[/green]")
        console.print(f"Would you like to open the HTML report in a browser? (Y/n): ", end="")
        choice = input().strip().lower()
        
        if choice != 'n':
            webbrowser.open(f"file://{os.path.abspath(html_report)}")
    except Exception as e:
        logger.error(f"Error generating HTML report: {str(e)}")
        console.print(f"[red]Error generating HTML report: {str(e)}[/red]")

if __name__ == "__main__":
    main()