
import sys
import json
import re
from pathlib import Path

from flask import (
    Flask,
    render_template,
    request,
    send_file,
    abort
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.engine import SecurityEngine
from core.logger import get_logger
from modules.reconnaissance.scanner import ReconScanner
from modules.web_analysis.analyzer import WebAnalyzer
from database.database import RoguePulseDatabase


# --------------------------------------------------
# APPLICATION CONFIGURATION
# --------------------------------------------------

app = Flask(__name__)

engine = SecurityEngine()
logger = get_logger("ROGUEPULSE.DASHBOARD")

recon_scanner = ReconScanner()
web_analyzer = WebAnalyzer()
database = RoguePulseDatabase()

REPORTS_DIRECTORY = PROJECT_ROOT / "reports"

REPORT_FILENAME_PATTERN = re.compile(
    r"^web_analysis_([0-9]+)\.txt$"
)


# --------------------------------------------------
# WEB ANALYSIS DATABASE FIELD MAPPING
# --------------------------------------------------

WEB_ANALYSIS_FIELDS = [
    "id",
    "target",
    "status_code",
    "content_type",
    "content_length",
    "forms",
    "inputs",
    "links",
    "images",
    "scripts",
    "analysis_date",
    "page_title",
    "title_found",
    "meta_description",
    "meta_generator",
    "headers_present",
    "headers_missing",
    "cookie_security",
    "content_truncated",
    "redirect_detected",
    "redirect_location_present"
]


# --------------------------------------------------
# GENERAL HELPER FUNCTIONS
# --------------------------------------------------

def parse_json_field(value, default=None):
    if default is None:
        default = []

    if value is None or value == "":
        return default

    if isinstance(value, (list, dict)):
        return value

    try:
        return json.loads(value)

    except (json.JSONDecodeError, TypeError):
        logger.warning("Unable to decode a stored JSON field.")
        return default


def convert_web_analysis_record(record):
    if record is None:
        return None

    try:
        if isinstance(record, dict):
            details = dict(record)

        else:
            details = dict(zip(WEB_ANALYSIS_FIELDS, record))

        details["headers_present"] = parse_json_field(
            details.get("headers_present"), []
        )

        details["headers_missing"] = parse_json_field(
            details.get("headers_missing"), []
        )

        details["cookie_security"] = parse_json_field(
            details.get("cookie_security"), []
        )

        boolean_fields = [
            "title_found",
            "content_truncated",
            "redirect_detected",
            "redirect_location_present"
        ]

        for field in boolean_fields:
            value = details.get(field)
            details[field] = bool(value) if value is not None else False

        return details

    except Exception:
        logger.exception("Unable to process web analysis record.")
        return None


def dashboard_context(**kwargs):
    context = {
        "app_name": "ROGUEPULSE",
        "version": "1.0.0",
        "engine_status": engine.get_status()
    }

    context.update(kwargs)

    return context


# --------------------------------------------------
# REPORT MANAGEMENT FUNCTIONS
# --------------------------------------------------

def get_available_reports():
    """
    Retrieve generated ROGUEPULSE web analysis reports.

    Only files matching the approved report filename
    pattern are included.
    """

    reports = []

    try:
        REPORTS_DIRECTORY.mkdir(parents=True, exist_ok=True)

        for report_file in REPORTS_DIRECTORY.iterdir():

            if not report_file.is_file():
                continue

            match = REPORT_FILENAME_PATTERN.fullmatch(
                report_file.name
            )

            if not match:
                continue

            try:
                resolved_path = report_file.resolve()

                if resolved_path.parent != REPORTS_DIRECTORY.resolve():
                    continue

                file_stats = resolved_path.stat()

                reports.append({
                    "id": int(match.group(1)),
                    "filename": report_file.name,
                    "generated": __import__("datetime").datetime.fromtimestamp(
                        file_stats.st_mtime
                    ).strftime("%Y-%m-%d %H:%M:%S"),
                    "size": file_stats.st_size
                })

            except OSError:
                logger.warning(
                    "Unable to inspect report file: %s",
                    report_file.name
                )

        reports.sort(
            key=lambda item: item["id"],
            reverse=True
        )

        return reports

    except OSError:
        logger.exception("Unable to retrieve generated reports.")
        return []


def get_valid_report_path(filename):
    """
    Resolve a report path safely.

    Rejects arbitrary filenames and paths outside
    the approved reports directory.
    """

    if not isinstance(filename, str):
        return None

    match = REPORT_FILENAME_PATTERN.fullmatch(filename)

    if not match:
        return None

    try:
        reports_root = REPORTS_DIRECTORY.resolve()
        report_path = (reports_root / filename).resolve()

        if report_path.parent != reports_root:
            return None

        if not report_path.is_file():
            return None

        return report_path

    except (OSError, RuntimeError):
        logger.warning("Unable to resolve requested report.")
        return None


# --------------------------------------------------
# OVERVIEW
# --------------------------------------------------


@app.route("/", methods=["GET", "POST"])
def dashboard():

    result = None
    target = ""

    # Handle target validation
    if request.method == "POST":

        target = request.form.get("target", "").strip()

        if engine.validate_target(target):

            result = {
                "status": "APPROVED",
                "message": "Local laboratory target approved."
            }

            logger.info("Dashboard approved a local target.")

        else:

            result = {
                "status": "REJECTED",
                "message": engine.scope_guard.explain_rejection()
            }

            logger.warning("Dashboard rejected a target.")

    # Retrieve dashboard statistics
    try:

        dashboard_statistics = database.get_dashboard_statistics()

        dashboard_statistics["total_reports"] = len(
            get_available_reports()
        )

    except Exception:

        logger.exception(
            "Unable to retrieve dashboard statistics."
        )

        dashboard_statistics = {
            "total_reconnaissance": 0,
            "total_web_analyses": 0,
            "total_reports": 0,
            "latest_activity": None
        }

    # Render dashboard
    return render_template(
        "index.html",
        **dashboard_context(
            result=result,
            target=target,
            active_page="overview",
            dashboard_statistics=dashboard_statistics
        )
    )


# --------------------------------------------------
# RECONNAISSANCE
# --------------------------------------------------

@app.route("/reconnaissance", methods=["GET", "POST"])
def reconnaissance_page():

    recon_result = None
    recon_error = None
    target = ""

    if request.method == "POST":

        target = request.form.get("target", "").strip()

        if not engine.validate_target(target):

            recon_error = engine.scope_guard.explain_rejection()

            logger.warning(
                "Reconnaissance rejected an invalid target."
            )

        else:

            try:

                if not hasattr(recon_scanner, "scan"):

                    recon_error = (
                        "Reconnaissance scanner is not available."
                    )

                else:

                    recon_result = recon_scanner.scan(target)

                    if recon_result is None:
                        recon_error = (
                            "The connection failed or analysis "
                            "could not be completed."
                        )

            except Exception:

                logger.exception(
                    "Dashboard reconnaissance error."
                )

                recon_error = (
                    "An unexpected error occurred during analysis."
                )

    return render_template(
        "index.html",
        **dashboard_context(
            target=target,
            recon_result=recon_result,
            recon_error=recon_error,
            active_page="reconnaissance"
        )
    )


# --------------------------------------------------
# WEB ANALYSIS
# --------------------------------------------------

@app.route("/web-analysis", methods=["GET", "POST"])
def web_analysis_page():

    target = ""
    web_result = None
    web_error = None

    if request.method == "POST":

        target = request.form.get("target", "").strip()

        if not engine.validate_target(target):

            web_error = engine.scope_guard.explain_rejection()

            logger.warning(
                "Dashboard web analysis rejected an invalid target."
            )

        else:

            try:

                web_result = web_analyzer.analyze(target)

                if web_result is None:

                    web_error = (
                        "Web analysis could not be completed. "
                        "Check the local server and try again."
                    )

                else:

                    logger.info(
                        "Dashboard web analysis completed successfully."
                    )

            except Exception:

                logger.exception(
                    "Dashboard web analysis failed."
                )

                web_error = (
                    "An unexpected error occurred during web analysis."
                )

    return render_template(
        "index.html",
        **dashboard_context(
            target=target,
            web_result=web_result,
            web_error=web_error,
            active_page="web-analysis"
        )
    )


# --------------------------------------------------
# RECONNAISSANCE HISTORY
# --------------------------------------------------

@app.route("/history")
def history_page():

    try:

        recon_history = database.get_history()

        return render_template(
            "index.html",
            **dashboard_context(
                recon_history=recon_history,
                active_page="history"
            )
        )

    except Exception:

        logger.exception(
            "Dashboard history retrieval failed."
        )

        return render_template(
            "index.html",
            **dashboard_context(
                recon_history=[],
                active_page="history",
                recon_error=(
                    "Unable to retrieve reconnaissance history."
                )
            )
        )


# --------------------------------------------------
# WEB ANALYSIS HISTORY
# --------------------------------------------------

@app.route("/web-analysis-history")
def web_analysis_history_page():

    try:

        web_history = database.get_web_analysis_history()

        return render_template(
            "index.html",
            **dashboard_context(
                web_history=web_history,
                active_page="web-analysis-history"
            )
        )

    except Exception:

        logger.exception(
            "Dashboard web analysis history retrieval failed."
        )

        return render_template(
            "index.html",
            **dashboard_context(
                web_history=[],
                active_page="web-analysis-history",
                recon_error=(
                    "Unable to retrieve web analysis history."
                )
            )
        )


# --------------------------------------------------
# INDIVIDUAL WEB ANALYSIS DETAILS
# --------------------------------------------------

@app.route("/web-analysis-history/<int:analysis_id>")
def web_analysis_details_page(analysis_id):

    try:

        analysis_record = database.get_web_analysis_by_id(
            analysis_id
        )

        analysis_details = convert_web_analysis_record(
            analysis_record
        )

        if analysis_record is None:

            logger.warning(
                "Web analysis record %s was not found.",
                analysis_id
            )

        elif analysis_details is None:

            logger.error(
                "Web analysis record %s could not be processed.",
                analysis_id
            )

        return render_template(
            "index.html",
            **dashboard_context(
                analysis_record=analysis_record,
                analysis_details=analysis_details,
                analysis_id=analysis_id,
                active_page="web-analysis-details"
            )
        )

    except Exception:

        logger.exception(
            "Web analysis details retrieval failed."
        )

        return render_template(
            "index.html",
            **dashboard_context(
                analysis_record=None,
                analysis_details=None,
                analysis_id=analysis_id,
                active_page="web-analysis-details",
                recon_error=(
                    "Unable to retrieve web analysis details."
                )
            )
        )


# --------------------------------------------------
# INDIVIDUAL RECONNAISSANCE DETAILS
# --------------------------------------------------

@app.route("/history/<int:scan_id>")
def scan_details_page(scan_id):

    try:

        scan_record = database.get_reconnaissance_by_id(
            scan_id
        )

        return render_template(
            "index.html",
            **dashboard_context(
                scan_record=scan_record,
                scan_id=scan_id,
                active_page="scan-details"
            )
        )

    except Exception:

        logger.exception(
            "Scan details retrieval failed."
        )

        return render_template(
            "index.html",
            **dashboard_context(
                scan_record=None,
                scan_id=scan_id,
                active_page="scan-details",
                recon_error=(
                    "Unable to retrieve scan details."
                )
            )
        )


# --------------------------------------------------
# REPORT LISTING
# --------------------------------------------------

@app.route("/reports")
def reports_page():

    reports_list = get_available_reports()

    return render_template(
        "index.html",
        **dashboard_context(
            reports_list=reports_list,
            active_page="reports"
        )
    )


# --------------------------------------------------
# VIEW INDIVIDUAL REPORT
# --------------------------------------------------

@app.route("/reports/view/<filename>")
def view_report_page(filename):

    report_path = get_valid_report_path(filename)

    if report_path is None:

        abort(404)

    try:

        report_content = report_path.read_text(
            encoding="utf-8",
            errors="replace"
        )

        return render_template(
            "index.html",
            **dashboard_context(
                report_filename=filename,
                report_content=report_content,
                active_page="report-view"
            )
        )

    except OSError:

        logger.exception(
            "Unable to read report: %s",
            filename
        )

        abort(404)


# --------------------------------------------------
# DOWNLOAD INDIVIDUAL REPORT
# --------------------------------------------------

@app.route("/reports/download/<filename>")
def download_report(filename):

    report_path = get_valid_report_path(filename)

    if report_path is None:

        abort(404)

    try:

        return send_file(
            report_path,
            as_attachment=True,
            download_name=filename,
            mimetype="text/plain"
        )

    except OSError:

        logger.exception(
            "Unable to download report: %s",
            filename
        )

        abort(404)


# --------------------------------------------------
# APPLICATION ENTRY POINT
# --------------------------------------------------

if __name__ == "__main__":

    print("Starting ROGUEPULSE dashboard...")
    print("Open http://127.0.0.1:5000 in your browser.")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
