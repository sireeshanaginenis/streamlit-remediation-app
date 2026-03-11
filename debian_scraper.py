# remediation_agent.py

import requests
from bs4 import BeautifulSoup
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class DebianRemediationAgent:

    def __init__(self):
        self.base_url = "https://security-tracker.debian.org/tracker/"

    # -----------------------------------------------------
    # STEP 1: Scrape Debian Security Tracker
    # -----------------------------------------------------
    def scrape_fixed_version(self, cve_id, distro="bookworm"):

        url = f"{self.base_url}{cve_id}"
        session = requests.Session()
        session.verify = False
        response = session.get(url)

        if response.status_code != 200:
            return {"error": "Failed to fetch Debian security tracker"}

        soup = BeautifulSoup(response.text, "html.parser")
        tables = soup.find_all("table")

        fixed_version = None
        package_name = None

        for table in tables:
            rows = table.find_all("tr")
            for row in rows:
                cells = row.find_all("td")
                if len(cells) >= 4:
                    pkg = cells[0].get_text(strip=True)
                    release = cells[2].get_text(strip=True).lower()
                    fixed = cells[3].get_text(strip=True)

                    if distro.lower() in release:
                        package_name = pkg
                        fixed_version = fixed

        if not fixed_version:
            return {"error": f"Fixed version not found for distro: {distro}"}

        return {
            "package": package_name,
            "fixed_version": fixed_version,
            "source": url
        }

    # -----------------------------------------------------
    # STEP 2: Generate Remediation Plan
    # -----------------------------------------------------
    def generate_remediation(self, cve_id, distro="bookworm"):

        scrape_data = self.scrape_fixed_version(cve_id, distro)

        if "error" in scrape_data:
            return {
                "summary": scrape_data["error"],
                "remediation": "Not Available",
                "sources": scrape_data.get("source", "Debian Security Tracker")
            }

        package_name = scrape_data["package"]
        fixed_version = scrape_data["fixed_version"]

        summary = f"""
CVE: {cve_id}
Package: {package_name}
Fixed Version: {fixed_version}
Distro: {distro}
Status: VULNERABLE
"""

        remediation_text = f"""Upgrade to version >= {fixed_version}

Dockerfile Option 1:
RUN apt update && apt install -y {package_name}

Dockerfile Option 2:
RUN apt install -y {package_name}={fixed_version}

Verification:
dpkg -l | grep {package_name}"""

        return {
            "summary": summary,
            "remediation": remediation_text,
            "sources": scrape_data["source"]
        }


# Function for Streamlit
agent = DebianRemediationAgent()

def debian_cve(cve_id):
    return agent.generate_remediation(cve_id=cve_id)