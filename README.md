AI-Powered SOC Assistant
By Sorbarikor Inene

This tool automatically scans a device for open ports and explains potential risks in plain language using AI (via DeepSeek or ChatGPT).

Features
	Automated Port Scanning: Uses Nmap to detect open ports.
	AI-Driven Analysis: Provides simple risk explanations from DeepSeek or ChatGPT.
	User-Friendly Interface: One-click scan with results displayed in plain language.
Setup
 Install Dependencies:
	pip install -r requirements.txt
 Run the Application:
	uvicorn main:app --reload
	python -m uvicorn main:app --reload (Powershell)
 Access the Interface:
	Open a web browser and navigate to http://127.0.0.1:8000.
	
Usage
 Click the "Scan" button to detect open ports on your device.
 The tool will generate a report explaining potential risks and recommendations.

API Configuration
	DeepSeek API: Replace <DeepSeek API URL> and DEEPSEEK_API_KEY with valid credentials.
	ChatGPT API: Replace OPENAI_API_KEY with your OpenAI API key for fallback analysis.

Notes
 Educational Use: This tool is for learning purposes. Always test on authorized networks.
 API Limits: Be aware of rate limits for APIs (e.g., OpenAI GPT-4 has usage costs).
 
 ---------------------------------------------------------------------------------------------------------
nmap Installation Guide
 The python-nmap library requires the nmap command-line tool to be installed and accessible in your system's PATH.

Windows Users
	Download nmap:
	 Get the Windows binary from nmap.org.
	 Choose the Stable Windows Installer (e.g., nmap-7.94-setup.exe).
	Install nmap:
	 Run the installer and follow the prompts.
	 During installation, note the installation directory (default: C:\Program Files\nmap).
	Add nmap to PATH:
	 Right-click This PC > Properties > Advanced system settings > Environment Variables.
	 Under System variables, find Path and click Edit.
	 Add the nmap installation directory (e.g., C:\Program Files\nmap).
	 Click OK and restart your terminal.
	Verify Installation:
	 powershellCopy
	 nmap -v
	Expected output:
	 Starting Nmap 7.94 ( https://nmap.org ) at 2024-07-26 10:00 EDT  
Linux/macOS Users
	bashCopy
	sudo apt-get install nmap  # Debian/Ubuntu  
	# or  
	brew install nmap  # macOS (Homebrew)  
Troubleshooting
	"nmap program was not found in path": Ensure nmap is installed and its directory is in your system's PATH.
Permission Issues: Run PowerShell as Administrator when modifying PATH.
