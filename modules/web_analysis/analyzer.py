import json
import requests

from html.parser import HTMLParser
from pathlib import Path
from datetime import datetime

from core.engine import SecurityEngine
from core.logger import get_logger
from database.database import RoguePulseDatabase


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

MAX_RESPONSE_SIZE = 1024 * 1024  # 1 MB

REQUEST_TIMEOUT = (3.05, 5)

USER_AGENT = "ROGUEPULSE/1.0 (Local Laboratory Analyzer)"


# --------------------------------------------------
# HTML STRUCTURE PARSER
# --------------------------------------------------

class PageStructureParser(HTMLParser):
    """Inspects the basic structure of an HTML document."""

    def __init__(self):
        super().__init__(convert_charrefs=True)

        self.title_found = False
        self.title_text = ""
        self.inside_title = False

        self.forms = 0
        self.inputs = 0
        self.links = 0
        self.images = 0
        self.scripts = 0

        self.meta_description = None
        self.meta_generator = None

    def _record_tag(self, tag, attrs):

        attributes = dict(attrs)

        if tag == "title":
            self.title_found = True
            self.inside_title = True

        elif tag == "form":
            self.forms += 1

        elif tag == "input":
            self.inputs += 1

        elif tag == "a":
            self.links += 1

        elif tag == "img":
            self.images += 1

        elif tag == "script":
            self.scripts += 1

        elif tag == "meta":

            name = attributes.get("name", "").lower()
            content = attributes.get("content", "")

            if name == "description":
                self.meta_description = content

            elif name == "generator":
                self.meta_generator = content

    def handle_starttag(self, tag, attrs):
        self._record_tag(tag, attrs)

    def handle_startendtag(self, tag, attrs):
        self._record_tag(tag, attrs)

    def handle_endtag(self, tag):

        if tag == "title":
            self.inside_title = False

    def handle_data(self, data):

        if self.inside_title:
            self.title_text += data


# --------------------------------------------------
# WEB ANALYZER
# --------------------------------------------------

class WebAnalyzer:
    """
    Performs defensive analysis of approved local
    laboratory web pages.
    """

    def __init__(self):

        self.engine = SecurityEngine()

        self.logger = get_logger(
            "ROGUEPULSE.WEB_ANALYSIS"
        )

        self.database = RoguePulseDatabase()

        self.security_headers = [
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy",
            "Strict-Transport-Security",
            "Permissions-Policy",
            "Cross-Origin-Opener-Policy",
            "Cross-Origin-Resource-Policy"
        ]

    # --------------------------------------------------
    # RESPONSE DOWNLOAD
    # --------------------------------------------------

    def _download_response(self, target):
        """Download a bounded response from an approved target."""

        with requests.get(
            target,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
            stream=True,
            verify=True,
            headers={
                "User-Agent": USER_AGENT
            }
        ) as response:

            content = bytearray()
            truncated = False

            for chunk in response.iter_content(
                chunk_size=8192
            ):

                if not chunk:
                    continue

                remaining = MAX_RESPONSE_SIZE - len(content)

                if len(chunk) > remaining:
                    content.extend(chunk[:remaining])
                    truncated = True
                    break

                content.extend(chunk)

                if len(content) >= MAX_RESPONSE_SIZE:
                    truncated = True
                    break

            encoding = response.encoding or "utf-8"

            page_content = bytes(content).decode(
                encoding,
                errors="replace"
            )

            return {
                "status_code": response.status_code,
                "content_type": response.headers.get(
                    "Content-Type",
                    "Not disclosed"
                ),
                "content_length": len(content),
                "headers": dict(response.headers),
                "cookies": list(response.cookies),
                "page_content": page_content,
                "content_truncated": truncated
            }

    # --------------------------------------------------
    # MAIN ANALYSIS
    # --------------------------------------------------

    def analyze(self, target):

        if not self.engine.validate_target(target):

            self.logger.warning(
                "Web analysis rejected an invalid target."
            )

            print("\n[!] Target rejected.")
            print(
                "Only approved local laboratory targets are allowed."
            )

            return None

        print("\n" + "=" * 60)
        print("          ROGUEPULSE WEB ANALYSIS")
        print("=" * 60)

        print("\n[+] Target:", target)

        try:

            response_data = self._download_response(target)

            parser = PageStructureParser()

            content_type = response_data["content_type"]

            if "html" in content_type.lower():

                parser.feed(
                    response_data["page_content"]
                )

            response_headers = response_data["headers"]

            results = {

                # Original database fields

                "target": target,

                "status_code": response_data["status_code"],

                "content_type": content_type,

                "content_length": response_data["content_length"],

                "forms": parser.forms,
                "inputs": parser.inputs,
                "links": parser.links,
                "images": parser.images,
                "scripts": parser.scripts,

                # Extended analysis fields

                "page_title": parser.title_text.strip(),

                "title_found": parser.title_found,

                "meta_description": parser.meta_description,

                "meta_generator": parser.meta_generator,

                "headers_present": [],

                "headers_missing": [],

                "cookie_security": [],

                "content_truncated": response_data[
                    "content_truncated"
                ],

                "redirect_detected": (
                    300 <= response_data["status_code"] < 400
                ),

                "redirect_location_present": (
                    "Location" in response_headers
                )
            }

            # --------------------------------------------------
            # SECURITY HEADER REVIEW
            # --------------------------------------------------

            normalized_headers = {
                name.lower(): value
                for name, value in response_headers.items()
            }

            for header in self.security_headers:

                if header.lower() in normalized_headers:

                    results["headers_present"].append(header)

                else:

                    results["headers_missing"].append(header)

            # --------------------------------------------------
            # COOKIE SECURITY REVIEW
            # --------------------------------------------------

            for cookie in response_data["cookies"]:

                results["cookie_security"].append({

                    "name": cookie.name,

                    "secure": bool(cookie.secure),

                    "httponly": bool(
                        cookie.has_nonstandard_attr("HttpOnly")
                    ),

                    "samesite": cookie.get_nonstandard_attr(
                        "SameSite"
                    )

                })

            # --------------------------------------------------
            # DISPLAY RESPONSE INFORMATION
            # --------------------------------------------------

            print("\n--- RESPONSE INFORMATION ---")

            print("HTTP status:", results["status_code"])
            print("Content type:", results["content_type"])
            print("Content length:", results["content_length"])
            print("Response truncated:", results["content_truncated"])

            print("\n--- HTML STRUCTURE ---")

            print(
                "Page title:",
                results["page_title"] or "Not found"
            )

            print("Forms:", results["forms"])
            print("Input fields:", results["inputs"])
            print("Links:", results["links"])
            print("Images:", results["images"])
            print("Scripts:", results["scripts"])

            print("\n--- METADATA ---")

            print(
                "Description:",
                results["meta_description"] or "Not found"
            )

            print(
                "Generator:",
                results["meta_generator"] or "Not found"
            )

            print("\n--- SECURITY HEADER REVIEW ---")

            for header in results["headers_present"]:

                print("[+] PRESENT:", header)

            for header in results["headers_missing"]:

                print("[-] MISSING:", header)

            print("\n--- COOKIE SECURITY REVIEW ---")

            if results["cookie_security"]:

                for cookie in results["cookie_security"]:

                    print("Cookie:", cookie["name"])
                    print("Secure:", cookie["secure"])
                    print("HttpOnly:", cookie["httponly"])
                    print("SameSite:", cookie["samesite"])

            else:

                print("No cookies were returned.")

            print("\n--- RESPONSE STATUS ---")

            print(
                "Redirect detected:",
                results["redirect_detected"]
            )

            print(
                "Redirect location present:",
                results["redirect_location_present"]
            )

            print("\n[+] Web analysis completed.")

            # --------------------------------------------------
            # DATABASE STORAGE
            # --------------------------------------------------

            self.database.save_web_analysis(results)

            print(
                "[+] Web analysis results saved to database."
            )

            self.logger.info(
                "Local web analysis completed: status=%s",
                response_data["status_code"]
            )

            return results

        except requests.Timeout:

            self.logger.warning(
                "Web analysis request timed out: %s",
                target
            )

            print("\n[!] Request timed out.")

            return None

        except requests.RequestException as error:

            self.logger.error(
                "Web analysis request failed: %s",
                error
            )

            print("\n[!] Request failed:", error)

            return None

        except Exception:

            self.logger.exception(
                "Unexpected web analysis failure."
            )

            print(
                "\n[!] An unexpected analysis error occurred."
            )

            return None

    # --------------------------------------------------
    # REPORT EXPORT
    # --------------------------------------------------

    def export_report(self, analysis_id):
        """Export a complete saved analysis as a text report."""

        record = self.database.get_web_analysis_by_id(
            analysis_id
        )

        if record is None:

            self.logger.warning(
                "Report export failed: record %s not found.",
                analysis_id
            )

            return None

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

        # Decode stored JSON safely.

        try:
            present = json.loads(headers_present or "[]")
            missing = json.loads(headers_missing or "[]")
            cookies = json.loads(cookie_security or "[]")

        except json.JSONDecodeError:

            self.logger.exception(
                "Invalid JSON data in analysis record %s.",
                scan_id
            )

            present = []
            missing = []
            cookies = []

        report_directory = Path("reports")

        report_directory.mkdir(
            parents=True,
            exist_ok=True
        )

        report_path = report_directory / (
            f"web_analysis_{scan_id}.txt"
        )

        # --------------------------------------------------
        # FORMAT SECURITY HEADERS
        # --------------------------------------------------

        present_text = (
            "\n".join(f"[+] {header}" for header in present)
            if present else "None recorded."
        )

        missing_text = (
            "\n".join(f"[-] {header}" for header in missing)
            if missing else "None recorded."
        )

        # --------------------------------------------------
        # FORMAT COOKIE OBSERVATIONS
        # --------------------------------------------------

        if cookies:

            cookie_lines = []

            for cookie in cookies:

                cookie_lines.append(
                    f"""
Cookie Name: {cookie.get('name', 'Unknown')}
Secure: {cookie.get('secure', 'Unknown')}
HttpOnly: {cookie.get('httponly', 'Unknown')}
SameSite: {cookie.get('samesite', 'Unknown')}
""".strip()
                )

            cookies_text = "\n\n".join(cookie_lines)

        else:

            cookies_text = "No cookies were returned."

        # --------------------------------------------------
        # BUILD REPORT
        # --------------------------------------------------

        report_content = f"""
============================================================
                 ROGUEPULSE ANALYSIS REPORT
============================================================

REPORT GENERATED:
{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

ANALYSIS INFORMATION
------------------------------------------------------------
Analysis ID: {scan_id}
Target: {target}
HTTP Status: {status}
Content Type: {content_type}
Content Length: {content_length} bytes
Analysis Date: {analysis_date}

HTML STRUCTURE
------------------------------------------------------------
Page Title: {page_title or "Not detected"}
Title Found: {bool(title_found)}

Forms: {forms}
Input Fields: {inputs}
Links: {links}
Images: {images}
Scripts: {scripts}

METADATA
------------------------------------------------------------
Description: {meta_description or "Not detected"}
Generator: {meta_generator or "Not detected"}

SECURITY HEADER REVIEW
------------------------------------------------------------
HEADERS PRESENT:

{present_text}

HEADERS MISSING:

{missing_text}

COOKIE SECURITY REVIEW
------------------------------------------------------------
{cookies_text}

RESPONSE STATUS
------------------------------------------------------------
Content Truncated: {bool(content_truncated)}
Redirect Detected: {bool(redirect_detected)}
Redirect Location Present: {bool(redirect_location_present)}

NOTE:
Missing security headers are observations for review.
They do not independently establish that a vulnerability exists.

============================================================
                  END OF REPORT
============================================================
"""

        report_path.write_text(
            report_content,
            encoding="utf-8"
        )

        self.logger.info(
            "Web analysis report exported: %s",
            report_path
        )

        return report_path