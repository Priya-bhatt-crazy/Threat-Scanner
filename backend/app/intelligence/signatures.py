"""
Static threat intelligence data.

Known malware hashes and heuristic string patterns used by the file scanner.
Moved from the original main.py MALWARE_HASHES constant.
"""

# Mock database of known malware hashes (SHA256)
MALWARE_HASHES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Test.Malware.Signature (Zero Byte Mock)",
    "5e8837cd006820f303791e84c4f507b3b12354a654817e24b480773c091911d9": "Trojan.Generic.CryptoMiner",
    "cf27db95f70b7c3d11b23a7894a4c6c06ebc60e5757d598687747e9231f82d1b": "Ransomware.WannaCry.Shadow",
}

# Static string heuristics scanned in the first 10 KB of a file
SUSPICIOUS_INDICATORS = {
    "powershell.exe -nop -w hidden": "Obfuscated PowerShell Script",
    "eval(base64_decode": "Encoded PHP Backdoor Shell",
    "os.system(": "System Execution Wrapper",
    "subprocess.Popen": "Shell Process Spawner",
    "WScript.Shell": "ActiveX Scripting Host Trojan",
}
