import sqlite3
import json

from core.engine import SecurityEngine
from core.logger import get_logger
from modules.reconnaissance.scanner import ReconScanner
from modules.web_analysis.analyzer import WebAnalyzer


class TerminalInterface:

    def __init__(self):
        self.engine = SecurityEngine()
        self.logger = get_logger("ROGUEPULSE.TERMINAL")
        self.recon_scanner = ReconScanner()
        self.web_analyzer = WebAnalyzer()

    def display_banner(self):
        print("\n" + "=" * 60)
        print("              R O G U E P U L S E")
        print("        AUTOMATED CYBERSECURITY PLATFORM")
        print("=" * 60)

    def display_menu(self):
        print("\nMAIN MENU")
        print("-" * 60)
        print("1. Platform information")
        print("2. Validate local laboratory target")
        print("3. System status")
        print("4. Run reconnaissance")
        print("5. View reconnaissance")
        print("6. Run web analysis")
        print("7. View web analysis history")
        print("8. View individual analysis history record")
        print("9. Export web analysis report")
        print("10. Export reconnaissance report")
        print("11. Exit")

    def display_history(self):
        records = self.recon_scanner.database.get_history()

        print("\n" + "=" * 60)
        print("      ROGUEPULSE RECONNAISSANCE HISTORY")
        print("=" * 60)

        if not records:
            print("\nNo reconnaissance records found.")
            return

        for record in records:
            scan_id, target, status, response_time, server, scan_date = record

            print(f"\nScan ID: {scan_id}")
            print(f"Target: {target}")
            print(f"HTTP Status: {status}")
            print(f"Response Time: {response_time} ms")
            print(f"Server: {server}")
            print(f"Date: {scan_date}")
            print("-" * 60)

        print(f"\nTotal records: {len(records)}")

    def display_web_history(self):
        records = self.web_analyzer.database.get_web_analysis_history()

        print("\n" + "=" * 60)
        print("     ROGUEPULSE WEB ANALYSIS HISTORY")
        print("=" * 60)

        if not records:
            print("\nNo web analysis records found.")
            return

        for record in records:
            (
                scan_id,
                target,
                status,
                content_type,
                content_length,
                forms,
                inputs,
                links,
                images,
                scripts,
                analysis_date,
            ) = record

            print(f"\nAnalysis ID: {scan_id}")
            print(f"Target: {target}")
            print(f"HTTP Status: {status}")
            print(f"Content Type: {content_type}")
            print(f"Content Length: {content_length} bytes")

            print("\nHTML STRUCTURE")
            print(f"Forms: {forms}")
            print(f"Input fields: {inputs}")
            print(f"Links: {links}")
            print(f"Images: {images}")
            print(f"Scripts: {scripts}")

            print(f"\nAnalysis Date: {analysis_date}")
            print("_" * 60)

        print(f"\nTotal web analysis records: {len(records)}")

    def display_web_analysis_by_id(self):
        print("\n" + "=" * 60)
        print("    ROGUEPULSE ANALYSIS RECORD LOOKUP")
        print("=" * 60)

        try:
            analysis_id = int(
                input("\nEnter Analysis ID: ").strip()
            )

        except ValueError:
            print("\n[!] Please enter a valid numeric ID.")
            return

        try:
            record = self.web_analyzer.database.get_web_analysis_by_id(
                analysis_id
            )

            if record is None:
                print("\n[!] No analysis record found with that ID.")
                return

            (
                scan_id,
                target,
                status,
                content_type,
                content_length,
                forms,
                inputs,
                links,
                images,
                scripts,
                analysis_date,
                page_title,
                title_found,
                meta_description,
                meta_generator,
                headers_present,
                headers_missing,
                cookie_security,
                content_truncated,
                redirect_detected,
                redirect_location_present
            ) = record

            print("\n--- ANALYSIS DETAILS ---")
            print("Analysis ID:", scan_id)
            print("Target:", target)
            print("HTTP Status:", status)
            print("Content Type:", content_type)
            print("Content Length:", content_length, "bytes")

            print("\n--- HTML STRUCTURE ---")
            print("Page Title:", page_title or "Not detected")
            print("Title Found:", bool(title_found))
            print("Forms:", forms)
            print("Input fields:", inputs)
            print("Links:", links)
            print("Images:", images)
            print("Scripts:", scripts)

            print("\n--- METADATA ---")
            print("Description:", meta_description or "Not detected")
            print("Generator:", meta_generator or "Not detected")

            print("\n--- SECURITY HEADER REVIEW ---")

            present = json.loads(headers_present or "[]")
            missing = json.loads(headers_missing or "[]")

            print("Headers Present:")
            if present:
                for header in present:
                    print(" [+]", header)
            else:
                print(" None recorded.")

            print("Headers Missing:")
            if missing:
                for header in missing:
                    print(" [-]", header)
            else:
                print(" None recorded.")

            print("\n--- COOKIE SECURITY ---")

            cookies = json.loads(cookie_security or "[]")

            if cookies:
                for cookie in cookies:
                    print(" -", cookie)
            else:
                print("No cookie observations recorded.")

            print("\n--- RESPONSE STATUS ---")
            print("Content Truncated:", bool(content_truncated))
            print("Redirect Detected:", bool(redirect_detected))
            print(
                "Redirect Location Present:",
                bool(redirect_location_present)
            )

            print("\nAnalysis Date:", analysis_date)

        except (sqlite3.Error, json.JSONDecodeError, TypeError, ValueError) as error:
            print("\n[!] Unable to display analysis record:", error)

        except Exception:
            self.logger.exception(
                "Unexpected error displaying web analysis record."
            )
            print("\n[!] An unexpected error occurred.")

    def display_export_report(self):
        print("\n" + "=" * 60)
        print("    ROGUEPULSE REPORT EXPORT")
        print("=" * 60)

        try:
            analysis_id = int(
                input("\nEnter Analysis ID to export: ").strip()
            )

            report_path = self.web_analyzer.export_report(
                analysis_id
            )

            if report_path is None:
                print("\n[!] No analysis record found.")
                return

            print("\n[+] Report successfully generated.")
            print("[+] Saved to:", report_path)

        except ValueError:
            print("\n[!] Please enter a valid numeric ID.")

        except OSError as error:
            print("\n[!] Report export failed:", error)

    def display_recon_export(self):
        print("\n" + "=" * 60)
        print("       ROGUEPULSE RECONNAISSANCE EXPORT")
        print("=" * 60)

        try:
            scan_id = int(
                input("\nEnter Reconnaissance ID to export: ").strip()
            )

            report_path = self.recon_scanner.export_report(
                scan_id
            )

            if report_path is None:
                print("\n[!] No reconnaissance record found.")
                return

            print("\n[+] Report successfully generated.")
            print("[+] Saved to:", report_path)

        except ValueError:
            print("\n[!] Please enter a valid numeric ID.")

        except OSError as error:
            print("\n[!] Report export failed:", error)

    def run(self):
        while True:
            self.display_banner()
            self.display_menu()

            choice = input("\nSelect an option: ").strip()

            if choice == "1":
                information = self.engine.get_information()

                print("\nPLATFORM INFORMATION")
                for key, value in information.items():
                    print(f"{key}: {value}")

            elif choice == "2":
                target = input(
                    "\nEnter local laboratory URL: "
                ).strip()

                if self.engine.validate_target(target):
                    print("\n[+] Target approved.")
                    self.logger.info("Local target approved.")
                else:
                    print("\n[-] Target rejected.")
                    print(
                        "Only localhost laboratory targets "
                        "are permitted."
                    )
                    self.logger.warning("Target rejected.")

            elif choice == "3":
                print(
                    "\nEngine status:",
                    self.engine.get_status()
                )

            elif choice == "4":
                target = input(
                    "\nEnter local laboratory URL: "
                ).strip()

                self.recon_scanner.scan(target)

            elif choice == "5":
                self.display_history()

            elif choice == "6":
                target = input(
                    "\nEnter local laboratory URL: "
                ).strip()

                self.web_analyzer.analyze(target)

            elif choice == "7":
                self.display_web_history()

            elif choice == "8":
                self.display_web_analysis_by_id()

            elif choice == "9":
                self.display_export_report()

            elif choice == "10":
                self.display_recon_export()

            elif choice == "11":
                self.engine.shutdown()
                print("\nROGUEPULSE shutting down.")
                break

            else:
                print("\n[!] Invalid selection.")

            input("\nPress Enter to continue...")