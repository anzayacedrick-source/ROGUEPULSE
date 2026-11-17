import sqlite3
import json
from pathlib import Path


class RoguePulseDatabase:
    """Manages the ROGUEPULSE local database."""

    def __init__(self):
        self.database_directory = Path("database")
        self.database_directory.mkdir(exist_ok=True)

        self.database_path = (
            self.database_directory / "roguepulse.db"
        )

        self.initialize_database()

    def connect(self):
        return sqlite3.connect(self.database_path)

    def initialize_database(self):
        with self.connect() as connection:
            cursor = connection.cursor()

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS reconnaissance (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    status_code INTEGER,
                    response_time_ms REAL,
                    server TEXT,
                    scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS web_analysis (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    status_code INTEGER,
                    content_type TEXT,
                    content_length INTEGER,
                    forms INTEGER,
                    inputs INTEGER,
                    links INTEGER,
                    images INTEGER,
                    scripts INTEGER,
                    analysis_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Safely add new columns to existing databases.
            existing_columns = {
                row[1]
                for row in cursor.execute(
                    "PRAGMA table_info(web_analysis)"
                ).fetchall()
            }

            new_columns = {
                "page_title": "TEXT",
                "title_found": "INTEGER",
                "meta_description": "TEXT",
                "meta_generator": "TEXT",
                "headers_present": "TEXT",
                "headers_missing": "TEXT",
                "cookie_security": "TEXT",
                "content_truncated": "INTEGER",
                "redirect_detected": "INTEGER",
                "redirect_location_present": "INTEGER"
            }

            for column_name, column_type in new_columns.items():
                if column_name not in existing_columns:
                    cursor.execute(
                        f"ALTER TABLE web_analysis "
                        f"ADD COLUMN {column_name} {column_type}"
                    )

            connection.commit()

    def save_scan(self, results):
        with self.connect() as connection:
            cursor = connection.cursor()

            cursor.execute("""
                INSERT INTO reconnaissance (
                    target,
                    status_code,
                    response_time_ms,
                    server
                )
                VALUES (?, ?, ?, ?)
            """, (
                results["target"],
                results["status_code"],
                results["response_time_ms"],
                results["server"]
            ))

            connection.commit()

        return True

    def save_web_analysis(self, results):
        with self.connect() as connection:
            cursor = connection.cursor()

            cursor.execute("""
                INSERT INTO web_analysis (
                    target,
                    status_code,
                    content_type,
                    content_length,
                    forms,
                    inputs,
                    links,
                    images,
                    scripts,
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
                )
                VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
            """, (
                results["target"],
                results["status_code"],
                results["content_type"],
                results["content_length"],
                results["forms"],
                results["inputs"],
                results["links"],
                results["images"],
                results["scripts"],
                results.get("page_title"),
                int(bool(results.get("title_found", False))),
                results.get("meta_description"),
                results.get("meta_generator"),
                json.dumps(results.get("headers_present", [])),
                json.dumps(results.get("headers_missing", [])),
                json.dumps(results.get("cookie_security", [])),
                int(bool(results.get("content_truncated", False))),
                int(bool(results.get("redirect_detected", False))),
                int(bool(results.get("redirect_location_present", False)))
            ))

            connection.commit()

        return True

    def get_history(self):
        with self.connect() as connection:
            cursor = connection.cursor()

            cursor.execute("""
                SELECT id, target, status_code,
                       response_time_ms, server, scan_date
                FROM reconnaissance
                ORDER BY id DESC
            """)

            return cursor.fetchall()

    def get_reconnaissance_by_id(self, scan_id):
        """Retrieve one reconnaissance record by its ID."""

        with self.connect() as connection:
            cursor = connection.cursor()

            cursor.execute("""
                SELECT id, target, status_code,
                       response_time_ms, server, scan_date
                FROM reconnaissance
                WHERE id = ?
            """, (scan_id,))

            return cursor.fetchone()

    def get_web_analysis_history(self):
        """Retrieve all saved web analysis records."""

        with self.connect() as connection:
            cursor = connection.cursor()

            cursor.execute("""
                SELECT id, target, status_code, content_type,
                       content_length, forms, inputs, links,
                       images, scripts, analysis_date
                FROM web_analysis
                ORDER BY id DESC
            """)

            return cursor.fetchall()

    def get_web_analysis_by_id(self, analysis_id):
        """Retrieve one web analysis record with extended findings."""

        with self.connect() as connection:
            cursor = connection.cursor()

            cursor.execute("""
                SELECT id, target, status_code, content_type,
                       content_length, forms, inputs, links,
                       images, scripts, analysis_date,
                       page_title, title_found, meta_description,
                       meta_generator, headers_present,
                       headers_missing, cookie_security,
                       content_truncated, redirect_detected,
                       redirect_location_present
                FROM web_analysis
                WHERE id = ?
            """, (analysis_id,))

            return cursor.fetchone()

    
    def get_dashboard_statistics(self):
        """Retrieve database statistics for the dashboard."""

        with self.connect() as connection:
            cursor = connection.cursor()

            # Total reconnaissance records
            cursor.execute("""
                SELECT COUNT(*)
                FROM reconnaissance
            """)

            total_reconnaissance = cursor.fetchone()[0]

            # Total web analysis records
            cursor.execute("""
                SELECT COUNT(*)
                FROM web_analysis
            """)

            total_web_analyses = cursor.fetchone()[0]

            # Most recent activity across both analysis tables
            cursor.execute("""
                SELECT activity_type, target, activity_date
                FROM (
                    SELECT
                        'Reconnaissance' AS activity_type,
                        target,
                        scan_date AS activity_date,
                        id
                    FROM reconnaissance

                    UNION ALL

                    SELECT
                        'Web Analysis' AS activity_type,
                        target,
                        analysis_date AS activity_date,
                        id
                    FROM web_analysis
                )
                ORDER BY activity_date DESC, id DESC
                LIMIT 1
            """)

            latest_activity = cursor.fetchone()

            return {
                "total_reconnaissance": total_reconnaissance,
                "total_web_analyses": total_web_analyses,
                "latest_activity": latest_activity
            }

    def get_dashboard_analytics(self):
        """Retrieve seven-day activity trends and recent activity."""

        with self.connect() as connection:
            cursor = connection.cursor()

            # Generate the last seven calender days.
            # Include days with zero recorded activity.

            cursor.execute("""
                WITH RECURSIVE dates(day) AS(
                    SELECT date('now', '-6 days')

                    UNION ALL

                    SELECT date(day, '+1 day')
                    FROM dates
                    WHERE day < date('now')
                ),

                daily_activity AS(
                    SELECT
                        date(scan_date) AS activity_day,
                        COUNT(*) AS reconnaissance_count,
                        0 AS web_analysis_count
                    FROM reconnaissance
                    WHERE date(scan_date) >= date('now', '-6 days')
                    GROUP BY date(scan_date)

                    UNION ALL

                    SELECT
                        date(analysis_date) AS activity_day,
                        0 AS reconnaissance_count,
                        COUNT(*) AS web_analysis_count
                    FROM web_analysis
                    WHERE date(analysis_date) >= date('now', '-6 days')
                    GROUP BY date(analysis_date)        
                )

                SELECT
                    dates.day,
                    COALESCE(SUM(daily_activity.reconnaissance_count), 0),
                    COALESCE(SUM(daily_activity.web_analysis_count), 0)

                FROM dates

                LEFT JOIN daily_activity
                    ON dates.day = daily_activity.activity_day

                GROUP BY dates.day
                ORDER BY dates.day ASC        
            """)

            activity_trends = cursor.fetchall()

            # Retrieve the ten most recent activities.
            cursor.execute("""
                SELECT activity_type, target, activity_date
                FROM(
                    SELECT
                        'Reconnaissance' AS activity_type,
                        target,
                        scan_date AS activity_date,
                        id
                    FROM reconnaissance

                    UNION ALL

                    SELECT
                        'Web Analysis' AS activity_type,
                        target,
                        analysis_date AS activity_date,
                        id
                    FROM web_analysis        
                )

                ORDER BY activity_date DESC, id DESC
                LIMIT 10
            """)

            recent_activity = cursor.fetchall()

            return {
                "activity_trends": activity_trends,
                "recent_activity": recent_activity
            }