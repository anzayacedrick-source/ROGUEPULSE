import time
import requests

from database.database import RoguePulseDatabase
from core.engine import SecurityEngine
from core.logger import get_logger


class ReconScanner:
    """Performs basic HTTP analysis on local lab targets."""

    def __init__(self):
        self.engine = SecurityEngine()
        self.logger = get_logger("ROGUEPULSE.RECON")
        self.database = RoguePulseDatabase()

        self.security_headers = {
            "Content-Security-Policy":
                "Helps control permitted content sources",
            "Strict-Transport-Security":
                "Helps enforce HTTPS connections",
            "X-Content-Type-Options":
                "Helps prevent MIME-type sniffing",
            "X-Frame-Options":
                "Helps control iframe embedding",
            "Referrer-Policy":
                "Controls referrer information"
        }

    def scan(self, target):
        if not self.engine.validate_target(target):
            print("\n[!] Target rejected.")
            print("Only approved local lab targets are allowed.")
            return None

        print("\n" + "=" * 55)
        print("       ROGUEPULSE RECONNAISSANCE")
        print("=" * 55)

        print("\n[+] Target:", target)

        try:
            start_time = time.perf_counter()

            response = requests.get(
                target,
                timeout=5,
                allow_redirects=False
            )

            elapsed = round(
                (time.perf_counter() - start_time) * 1000,
                2
            )

            results = {
                "target": target,
                "status_code": response.status_code,
                "response_time_ms": elapsed,
                "http_version": response.raw.version,
                "server": response.headers.get(
                    "Server", "Not disclosed"
                ),
                "headers_present": [],
                "headers_missing": []
            }

            for header in self.security_headers:
                if header in response.headers:
                    results["headers_present"].append(header)
                else:
                    results["headers_missing"].append(header)

            print("\n--- HTTP INFORMATION ---")
            print("Status:", results["status_code"])
            print("Response time:", elapsed, "ms")
            print("Server:", results["server"])

            print("\n--- SECURITY HEADER REVIEW ---")

            for header in results["headers_present"]:
                print("[+] PRESENT:", header)

            for header in results["headers_missing"]:
                print("[-] MISSING:", header)

            print("\n[+] Local HTTP analysis completed.")
            self.database.save_scan(results)
            print("[+] Reconnaissance resuls saved to database.")

            self.logger.info(
                "Local HTTP analysis completed: status=%s",
                response.status_code
            )

            return results

        except requests.RequestException as error:
            print("\n[!] Connection failed:", error)
            self.logger.error("HTTP analysis failed: %s", error)
            return None

    def export_report(self, scan_id):
        """Export one saved reconnaissance scan."""

        from pathlib import Path
        from datetime import datetime

        record = self.database.get_reconnaissance_by_id(
            scan_id
        )

        if record is None:
            return None

        (
            record_id,
            target,
            status_code,
            response_time,
            server,
            scan_date
        ) = record

        report_directory = Path("reports")
        report_directory.mkdir(exist_ok=True)

        report_path = report_directory / (
            f"reconnaissance_{record_id}.txt"
        )

        report_content = f"""
============================================================
              ROGUEPULSE RECONNAISSANCE REPORT
============================================================

REPORT GENERATED: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

SCAN INFORMATION
------------------------------------------------------------
Scan ID: {record_id}
Target: {target}
HTTP Status: {status_code}
Response Time: {response_time} ms
Server: {server}
Scan Date: {scan_date}

============================================================
                  END OF REPORT
============================================================
"""

        report_path.write_text(
            report_content,
            encoding="utf-8"
        )

        return report_path    