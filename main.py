import socket
import nmap
import requests
import asyncio
import json
import logging

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
import openai

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# API Configuration
OPENAI_API_KEY = "PUT YOUR KEY HERE"
openai.api_key = OPENAI_API_KEY

logging.basicConfig(level=logging.INFO)

def perform_port_scan(target_ip):
    """Perform a port scan using python-nmap."""
    scanner = nmap.PortScanner()
    scan_results = {"ip": target_ip, "open_ports": []}
    try:
        scanner.scan(target_ip, arguments="-Pn -T4")
    except Exception as e:
        scan_results["error"] = f"Scan failed: {e}"
        logging.error(f"Port scan failed: {e}")
        return scan_results
    
    try:
        for protocol in scanner[target_ip].all_protocols():
            for port in scanner[target_ip][protocol]:
                port_info = scanner[target_ip][protocol][port]
                if port_info["state"] == "open":
                    scan_results["open_ports"].append({
                        "port": port,
                        "protocol": protocol,
                        "service": port_info.get("name", "unknown")
                    })
    except Exception as e:
        scan_results["error"] = f"Scan error: {e}"
        logging.error(f"Error parsing scan results: {e}")
    
    return scan_results

def get_local_ip():
    """Determine the local machine's IP address."""
    try:
        hostname = socket.gethostname()
        return socket.gethostbyname(hostname)
    except Exception:
        return "127.0.0.1"

def format_scan_data(scan_data):
    """Format scan results into a plain text list for ChatGPT."""
    ports = scan_data.get("open_ports", [])
    port_list = "\n".join(
        f"- **Port {port['port']} ({port['protocol']})**: {port['service']}"
        for port in ports
    )
    return port_list if ports else "No open ports found."

async def analyze_with_chatgpt(scan_data):
    """Generate analysis using ChatGPT API (fallback)."""
    prompt = f"""
You are a cybersecurity expert explaining open ports to a non-technical user.
Scan results: {format_scan_data(scan_data)}

First, tell the user you finished scanning and list the ports you found open.
After that, provide:
1. A bulleted list of open ports with brief descriptions.
2. A numbered list of actionable security recommendations for each port.

Keep the tone friendly and conversational. Avoid technical jargon.
"""
    try:
        completion = await openai.ChatCompletion.acreate(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=800,
            temperature=0.7,
        )
        analysis = completion.choices[0].message.content.strip()
        return {"source": "ChatGPT", "data": analysis}
    except Exception as e:
        return {"error": f"ChatGPT API error: {e}"}

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/scan", response_class=JSONResponse)
async def scan():
    """Perform scan and return analysis."""
    target_ip = get_local_ip()
    scan_results = perform_port_scan(target_ip)
    analysis = await analyze_with_chatgpt(scan_results)
    return analysis

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
