#!/usr/bin/env python3
# File: threat-intelligence.py
"""
SSHoney Threat Intelligence Integration
Analyzes SSHoney logs and enriches with threat intelligence data
"""

import argparse
import ipaddress
import json
import logging
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set

import geoip2.database
import geoip2.errors
import requests

# Configuration
CONFIG = {
    "log_file": "/var/log/sshoney/sshoney.log",
    "db_file": "/var/lib/sshoney/threat_intel.db",
    "geoip_db": "/usr/share/GeoIP/GeoLite2-City.mmdb",
    "update_interval": 3600,  # 1 hour
    "batch_size": 100,
    "api_timeout": 30,
    "max_workers": 10,
}


@dataclass
class ThreatData:
    ip: str
    first_seen: str
    last_seen: str
    connection_count: int
    threat_score: int
    categories: List[str]
    country: Optional[str] = None
    city: Optional[str] = None
    asn: Optional[str] = None
    is_malicious: bool = False
    sources: List[str] = None

    def __post_init__(self):
        if self.sources is None:
            self.sources = []


class ThreatIntelligence:
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.db_path = Path(config["db_file"])
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Initialize database
        self.init_database()

        # Load GeoIP database
        self.geoip_reader = None
        try:
            if Path(config["geoip_db"]).exists():
                self.geoip_reader = geoip2.database.Reader(config["geoip_db"])
        except Exception as e:
            self.logger.warning(f"Failed to load GeoIP database: {e}")

    def init_database(self):
        """Initialize SQLite database for threat intelligence"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS threat_intel (
                    ip TEXT PRIMARY KEY,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    connection_count INTEGER DEFAULT 1,
                    threat_score INTEGER DEFAULT 0,
                    categories TEXT,
                    country TEXT,
                    city TEXT,
                    asn TEXT,
                    is_malicious BOOLEAN DEFAULT 0,
                    sources TEXT,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ip_reputation (
                    ip TEXT PRIMARY KEY,
                    reputation_score INTEGER,
                    source TEXT,
                    last_checked TEXT,
                    data TEXT
                )
            """
            )

            # Create indexes
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_last_seen ON threat_intel(last_seen)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_threat_score ON threat_intel(threat_score)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_is_malicious ON threat_intel(is_malicious)"
            )

    def parse_sshoney_log(self, log_file: str) -> List[Dict]:
        """Parse SSHoney log file and extract connection data"""
        connections = []

        try:
            with open(log_file, "r") as f:
                for line in f:
                    if "ACCEPT" in line:
                        parts = line.strip().split()
                        if len(parts) >= 4:
                            timestamp = parts[0]
                            # Extract IP from host=x.x.x.x
                            host_part = next(
                                (p for p in parts if p.startswith("host=")), None
                            )
                            if host_part:
                                ip = host_part.split("=")[1]
                                connections.append({"timestamp": timestamp, "ip": ip})
        except FileNotFoundError:
            self.logger.error(f"Log file not found: {log_file}")
        except Exception as e:
            self.logger.error(f"Error parsing log file: {e}")

        return connections

    def get_geolocation(self, ip: str) -> Dict[str, Optional[str]]:
        """Get geolocation data for IP address"""
        geo_data = {"country": None, "city": None, "asn": None}

        if not self.geoip_reader:
            return geo_data

        try:
            response = self.geoip_reader.city(ip)
            geo_data["country"] = response.country.iso_code
            geo_data["city"] = response.city.name

            # Get ASN if available
            if hasattr(response, "traits") and response.traits.autonomous_system_number:
                geo_data["asn"] = f"AS{response.traits.autonomous_system_number}"

        except geoip2.errors.AddressNotFoundError:
            pass
        except Exception as e:
            self.logger.warning(f"GeoIP lookup failed for {ip}: {e}")

        return geo_data

    def check_virustotal(self, ip: str, api_key: str) -> Dict:
        """Check IP reputation using VirusTotal API"""
        if not api_key:
            return {}

        url = f"https://www.virustotal.com/vtapi/v2/ip-address/report"
        params = {"apikey": api_key, "ip": ip}

        try:
            response = requests.get(
                url, params=params, timeout=self.config["api_timeout"]
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            self.logger.warning(f"VirusTotal API error for {ip}: {e}")
            return {}

    def check_abuseipdb(self, ip: str, api_key: str) -> Dict:
        """Check IP reputation using AbuseIPDB API"""
        if not api_key:
            return {}

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}

        try:
            response = requests.get(
                url, headers=headers, params=params, timeout=self.config["api_timeout"]
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            self.logger.warning(f"AbuseIPDB API error for {ip}: {e}")
            return {}

    def check_greynoise(self, ip: str, api_key: str) -> Dict:
        """Check IP reputation using GreyNoise API"""
        if not api_key:
            return {}

        url = f"https://api.greynoise.io/v3/community/{ip}"
        headers = {"key": api_key}

        try:
            response = requests.get(
                url, headers=headers, timeout=self.config["api_timeout"]
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            self.logger.warning(f"GreyNoise API error for {ip}: {e}")
            return {}

    def enrich_ip_data(self, ip: str, api_keys: Dict[str, str]) -> ThreatData:
        """Enrich IP data with threat intelligence from multiple sources"""
        geo_data = self.get_geolocation(ip)

        # Initialize threat data
        threat_data = ThreatData(
            ip=ip,
            first_seen=datetime.now().isoformat(),
            last_seen=datetime.now().isoformat(),
            connection_count=1,
            threat_score=0,
            categories=[],
            **geo_data,
        )

        # Check multiple threat intelligence sources
        sources_data = {}

        if "virustotal" in api_keys:
            vt_data = self.check_virustotal(ip, api_keys["virustotal"])
            if vt_data:
                sources_data["virustotal"] = vt_data
                threat_data.sources.append("virustotal")

                # Calculate threat score from VT data
                if "detected_urls" in vt_data:
                    threat_data.threat_score += len(vt_data["detected_urls"]) * 10
                if "detected_downloaded_samples" in vt_data:
                    threat_data.threat_score += (
                        len(vt_data["detected_downloaded_samples"]) * 5
                    )

        if "abuseipdb" in api_keys:
            abuse_data = self.check_abuseipdb(ip, api_keys["abuseipdb"])
            if abuse_data and "data" in abuse_data:
                sources_data["abuseipdb"] = abuse_data
                threat_data.sources.append("abuseipdb")

                data = abuse_data["data"]
                threat_data.threat_score += data.get("abuseConfidencePercentage", 0)
                if data.get("categories"):
                    threat_data.categories.extend(
                        [str(cat) for cat in data["categories"]]
                    )

        if "greynoise" in api_keys:
            gn_data = self.check_greynoise(ip, api_keys["greynoise"])
            if gn_data:
                sources_data["greynoise"] = gn_data
                threat_data.sources.append("greynoise")

                if gn_data.get("noise", False):
                    threat_data.threat_score += 30
                if gn_data.get("riot", False):
                    threat_data.threat_score -= 20  # Common service, lower threat

        # Determine if IP is malicious based on threat score
        threat_data.is_malicious = threat_data.threat_score > 50

        # Store detailed reputation data
        self.store_reputation_data(ip, sources_data)

        return threat_data

    def store_reputation_data(self, ip: str, sources_data: Dict):
        """Store detailed reputation data in database"""
        with sqlite3.connect(self.db_path) as conn:
            for source, data in sources_data.items():
                conn.execute(
                    """
                    INSERT OR REPLACE INTO ip_reputation 
                    (ip, source, data, last_checked)
                    VALUES (?, ?, ?, ?)
                """,
                    (ip, source, json.dumps(data), datetime.now().isoformat()),
                )

    def update_threat_data(self, threat_data: ThreatData):
        """Update or insert threat data in database"""
        with sqlite3.connect(self.db_path) as conn:
            # Check if IP already exists
            cursor = conn.execute(
                "SELECT * FROM threat_intel WHERE ip = ?", (threat_data.ip,)
            )
            existing = cursor.fetchone()

            if existing:
                # Update existing record
                conn.execute(
                    """
                    UPDATE threat_intel SET
                        last_seen = ?,
                        connection_count = connection_count + 1,
                        threat_score = ?,
                        categories = ?,
                        country = COALESCE(?, country),
                        city = COALESCE(?, city),
                        asn = COALESCE(?, asn),
                        is_malicious = ?,
                        sources = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE ip = ?
                """,
                    (
                        threat_data.last_seen,
                        threat_data.threat_score,
                        ",".join(threat_data.categories),
                        threat_data.country,
                        threat_data.city,
                        threat_data.asn,
                        threat_data.is_malicious,
                        ",".join(threat_data.sources),
                        threat_data.ip,
                    ),
                )
            else:
                # Insert new record
                conn.execute(
                    """
                    INSERT INTO threat_intel 
                    (ip, first_seen, last_seen, connection_count, threat_score, 
                     categories, country, city, asn, is_malicious, sources)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        threat_data.ip,
                        threat_data.first_seen,
                        threat_data.last_seen,
                        threat_data.connection_count,
                        threat_data.threat_score,
                        ",".join(threat_data.categories),
                        threat_data.country,
                        threat_data.city,
                        threat_data.asn,
                        threat_data.is_malicious,
                        ",".join(threat_data.sources),
                    ),
                )

    def process_connections(self, connections: List[Dict], api_keys: Dict[str, str]):
        """Process connections with threat intelligence enrichment"""
        unique_ips = set(conn["ip"] for conn in connections)

        self.logger.info(
            f"Processing {len(unique_ips)} unique IPs from {len(connections)} connections"
        )

        # Process IPs in batches using thread pool
        with ThreadPoolExecutor(max_workers=self.config["max_workers"]) as executor:
            # Submit enrichment tasks
            future_to_ip = {
                executor.submit(self.enrich_ip_data, ip, api_keys): ip
                for ip in unique_ips
            }

            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    threat_data = future.result()
                    self.update_threat_data(threat_data)

                    if threat_data.is_malicious:
                        self.logger.warning(
                            f"Malicious IP detected: {ip} (score: {threat_data.threat_score})"
                        )

                except Exception as e:
                    self.logger.error(f"Error processing IP {ip}: {e}")

    def generate_report(self, days: int = 7) -> Dict:
        """Generate threat intelligence report"""
        cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()

        with sqlite3.connect(self.db_path) as conn:
            # Get statistics
            stats = {}

            # Total unique IPs
            cursor = conn.execute("SELECT COUNT(*) FROM threat_intel")
            stats["total_ips"] = cursor.fetchone()[0]

            # Recent activity
            cursor = conn.execute(
                "SELECT COUNT(*) FROM threat_intel WHERE last_seen >= ?", (cutoff_date,)
            )
            stats["recent_ips"] = cursor.fetchone()[0]

            # Malicious IPs
            cursor = conn.execute(
                "SELECT COUNT(*) FROM threat_intel WHERE is_malicious = 1 AND last_seen >= ?",
                (cutoff_date,),
            )
            stats["malicious_ips"] = cursor.fetchone()[0]

            # Top countries
            cursor = conn.execute(
                """
                SELECT country, COUNT(*) as count 
                FROM threat_intel 
                WHERE last_seen >= ? AND country IS NOT NULL
                GROUP BY country 
                ORDER BY count DESC 
                LIMIT 10
            """,
                (cutoff_date,),
            )
            stats["top_countries"] = dict(cursor.fetchall())

            # Top threat categories
            cursor = conn.execute(
                """
                SELECT categories, COUNT(*) as count 
                FROM threat_intel 
                WHERE last_seen >= ? AND categories != ''
                GROUP BY categories 
                ORDER BY count DESC 
                LIMIT 10
            """,
                (cutoff_date,),
            )
            stats["top_categories"] = dict(cursor.fetchall())

            # High-threat IPs
            cursor = conn.execute(
                """
                SELECT ip, threat_score, connection_count, country, categories
                FROM threat_intel 
                WHERE last_seen >= ? AND threat_score > 70
                ORDER BY threat_score DESC 
                LIMIT 20
            """,
                (cutoff_date,),
            )

            stats["high_threat_ips"] = [
                {
                    "ip": row[0],
                    "threat_score": row[1],
                    "connection_count": row[2],
                    "country": row[3],
                    "categories": row[4],
                }
                for row in cursor.fetchall()
            ]

        return stats

    def export_indicators(
        self, format_type: str = "json", min_threat_score: int = 50
    ) -> str:
        """Export threat indicators in various formats"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """
                SELECT ip, threat_score, categories, country, sources, last_seen
                FROM threat_intel 
                WHERE threat_score >= ? AND is_malicious = 1
                ORDER BY threat_score DESC
            """,
                (min_threat_score,),
            )

            indicators = [
                {
                    "ip": row[0],
                    "threat_score": row[1],
                    "categories": row[2].split(",") if row[2] else [],
                    "country": row[3],
                    "sources": row[4].split(",") if row[4] else [],
                    "last_seen": row[5],
                }
                for row in cursor.fetchall()
            ]

        if format_type == "json":
            return json.dumps(indicators, indent=2)
        elif format_type == "csv":
            import csv
            import io

            output = io.StringIO()
            writer = csv.DictWriter(
                output,
                fieldnames=[
                    "ip",
                    "threat_score",
                    "categories",
                    "country",
                    "sources",
                    "last_seen",
                ],
            )
            writer.writeheader()

            for indicator in indicators:
                # Flatten lists for CSV
                indicator["categories"] = ";".join(indicator["categories"])
                indicator["sources"] = ";".join(indicator["sources"])
                writer.writerow(indicator)

            return output.getvalue()
        elif format_type == "stix":
            # STIX 2.1 format for threat intelligence platforms
            import uuid

            stix_objects = []

            # Add bundle header
            bundle_id = str(uuid.uuid4())
            stix_objects.append(
                {"type": "bundle", "id": f"bundle--{bundle_id}", "objects": []}
            )

            for indicator in indicators:
                indicator_id = str(uuid.uuid4())
                stix_objects[0]["objects"].append(
                    {
                        "type": "indicator",
                        "spec_version": "2.1",
                        "id": f"indicator--{indicator_id}",
                        "created": indicator["last_seen"],
                        "modified": indicator["last_seen"],
                        "pattern": f"[ipv4-addr:value = '{indicator['ip']}']",
                        "labels": ["malicious-activity"],
                        "confidence": min(indicator["threat_score"], 100),
                        "custom_properties": {
                            "x_threat_score": indicator["threat_score"],
                            "x_country": indicator["country"],
                            "x_categories": indicator["categories"],
                            "x_sources": indicator["sources"],
                        },
                    }
                )

            return json.dumps(stix_objects[0], indent=2)

        return json.dumps(indicators, indent=2)

    def cleanup_old_data(self, days: int = 90):
        """Clean up old threat intelligence data"""
        cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "DELETE FROM threat_intel WHERE last_seen < ?", (cutoff_date,)
            )
            deleted_count = cursor.rowcount

            cursor = conn.execute(
                "DELETE FROM ip_reputation WHERE last_checked < ?", (cutoff_date,)
            )
            deleted_rep_count = cursor.rowcount

            self.logger.info(
                f"Cleaned up {deleted_count} old threat records and {deleted_rep_count} reputation records"
            )


def main():
    parser = argparse.ArgumentParser(
        description="SSHoney Threat Intelligence Integration"
    )
    parser.add_argument(
        "--config",
        "-c",
        default="/etc/sshoney/threat_intel.json",
        help="Configuration file path",
    )
    parser.add_argument(
        "--log-file", "-l", default=CONFIG["log_file"], help="SSHoney log file path"
    )
    parser.add_argument(
        "--report",
        "-r",
        action="store_true",
        help="Generate threat intelligence report",
    )
    parser.add_argument(
        "--export",
        "-e",
        choices=["json", "csv", "stix"],
        help="Export threat indicators",
    )
    parser.add_argument("--cleanup", action="store_true", help="Clean up old data")
    parser.add_argument(
        "--daemon", "-d", action="store_true", help="Run in daemon mode"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging"
    )

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # Load configuration
    config = CONFIG.copy()
    if Path(args.config).exists():
        with open(args.config) as f:
            config.update(json.load(f))

    # Load API keys from config
    api_keys = config.get("api_keys", {})

    # Initialize threat intelligence system
    ti = ThreatIntelligence(config)

    if args.cleanup:
        ti.cleanup_old_data()
        return

    if args.report:
        report = ti.generate_report()
        print(json.dumps(report, indent=2))
        return

    if args.export:
        indicators = ti.export_indicators(args.export)
        print(indicators)
        return

    if args.daemon:
        # Daemon mode - continuous processing
        logging.info("Starting threat intelligence daemon")

        while True:
            try:
                # Process new log entries
                connections = ti.parse_sshoney_log(args.log_file)
                if connections:
                    ti.process_connections(connections, api_keys)

                # Sleep before next iteration
                time.sleep(config["update_interval"])

            except KeyboardInterrupt:
                logging.info("Shutting down daemon")
                break
            except Exception as e:
                logging.error(f"Error in daemon loop: {e}")
                time.sleep(60)  # Wait before retrying
    else:
        # One-time processing
        connections = ti.parse_sshoney_log(args.log_file)
        if connections:
            ti.process_connections(connections, api_keys)


if __name__ == "__main__":
    main()

# Example configuration file: /etc/sshoney/threat_intel.json
"""
{
    "log_file": "/var/log/sshoney/sshoney.log",
    "db_file": "/var/lib/sshoney/threat_intel.db", 
    "geoip_db": "/usr/share/GeoIP/GeoLite2-City.mmdb",
    "update_interval": 3600,
    "batch_size": 100,
    "api_timeout": 30,
    "max_workers": 10,
    "api_keys": {
        "virustotal": "your_virustotal_api_key_here",
        "abuseipdb": "your_abuseipdb_api_key_here", 
        "greynoise": "your_greynoise_api_key_here"
    }
}
"""