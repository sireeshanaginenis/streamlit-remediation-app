# ubuntu_remediation_agent.py

import requests
from bs4 import BeautifulSoup
import re
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class UbuntuRemediationAgent:

    def __init__(self):
        self.base_url = "https://ubuntu.com/security/"

    # -----------------------------------------------------
    # STEP 1: Scrape Ubuntu Security CVE Page
    # -----------------------------------------------------
    def scrape_fixed_version(self, cve_id):
        url = f"{self.base_url}{cve_id}"
        session = requests.Session()
        session.verify = False
        response = session.get(url)

        if response.status_code != 200:
            return {"error": f"Failed to fetch Ubuntu security page: {response.status_code}"}

        soup = BeautifulSoup(response.text, "html.parser")

        table = soup.find("table", class_="cve-table")
        if not table:
            return {"error": "CVE table not found on page"}

        rows = table.find("tbody").find_all("tr")
        current_package = None

        for row in rows:

            # Detect new package section
            th = row.find("th")
            if th:
                current_package = th.get_text(strip=True)

            cells = row.find_all("td")
            if len(cells) < 2:
                continue

            release_txt = cells[0].get_text(" ", strip=True)
            status_txt = cells[1].get_text(" ", strip=True)

            # If Fixed exists
            if "fixed" in status_txt.lower():
                match = re.search(r"[Ff]ixed\s+([0-9A-Za-z\.\-\+~]+)", status_txt)
                if match:
                    return {
                        "package": current_package,
                        "release": release_txt,
                        "fixed_version": match.group(1).strip(),
                        "source": url
                    }

        return {"error": "No fixed version found in any Ubuntu release"}
        # -----------------------------------------------------
    # STEP 2: Generate Remediation Plan
    # -----------------------------------------------------
    def generate_remediation(self, cve_id):

        scrape_data = self.scrape_fixed_version(cve_id)
        print("scrape_data", scrape_data)

        if "error" in scrape_data:
            return {
                "summary": scrape_data["error"],
                "remediation": "Not Available",
                "sources": scrape_data.get("source", "Ubuntu Security")
            }

        package_name = scrape_data["package"]
        fixed_version = scrape_data["fixed_version"]
        release = scrape_data["release"]

        summary = f"""
    CVE: {cve_id}
    Package: {package_name}
    Ubuntu Release: {release}
    Fixed Version: {fixed_version}
    Status: VULNERABLE
    """

        remediation_text = f"""Upgrade to version >= {fixed_version}

    Option 1 (Recommended):
    sudo apt update
    sudo apt install --only-upgrade {package_name}

    Option 2 (Install Specific Version):
    sudo apt install {package_name}={fixed_version}

    Verification:
    dpkg -l | grep {package_name}
    """

        return {
            "summary": summary.strip(),
            "remediation": remediation_text.strip(),
            "sources": scrape_data["source"]
        }


# Function for Streamlit
agent = UbuntuRemediationAgent()

def ubuntu_cve(cve_id):
    return agent.generate_remediation(cve_id)



#result = ubuntu_cve(cve_id= "CVE-2025-1153")
#print(result)