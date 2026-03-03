#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cortex analyzer to enrich IP addresses with VirusTotal v3."""

from cortexutils.analyzer import Analyzer
import json
import ipaddress
import urllib.request
import urllib.error
import logging
import ssl
import socket
from datetime import datetime

class IPEnrichVirusTotal(Analyzer):
    """Look up IPv4/IPv6 indicators and return normalized threat context."""
    
    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def _validate_ip(self, ip_str):
        """Validate IP syntax and return `(is_valid, ip_obj, is_public)`.

        `is_public` excludes private, loopback, reserved, multicast, and link-local ranges.
        """
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
            
            is_public = not (ip_obj.is_private or ip_obj.is_loopback or 
                           ip_obj.is_reserved or ip_obj.is_multicast or
                           ip_obj.is_link_local or ip_obj.is_unspecified)
            
            return True, ip_obj, is_public
            
        except ValueError as e:
            self.logger.warning(f"Invalid IP format: {ip_str} - {str(e)}")
            return False, None, False
    
    def _is_resolvable(self, ip_str):
        """Best-effort reverse DNS check used as contextual signal."""
        try:
            socket.gethostbyaddr(ip_str)
            return True
        except (socket.herror, socket.gaierror):
            return False
        except Exception as e:
            self.logger.warning(f"Error checking IP resolution: {str(e)}")
            return False

    def _http_get_json(self, url, headers=None, timeout=10, verify_ssl=True):
        """Execute HTTP GET and parse JSON response.

        Returns `None` on network, HTTP status, or decoding errors.
        """
        try:
            if not headers:
                headers = {}
            
            req = urllib.request.Request(url, headers=headers)
            
            if verify_ssl:
                ctx = ssl.create_default_context()
            else:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                self.logger.warning("SSL verification disabled")
            
            self.logger.info(f"Making API request to VirusTotal: {url}")
            
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                if r.status != 200:
                    self.logger.warning(f"API returned status {r.status}")
                    return None
                    
                data = r.read().decode("utf-8", errors="replace")
                
                try:
                    return json.loads(data)
                except json.JSONDecodeError as e:
                    self.logger.error(f"Failed to parse JSON response: {e}")
                    return None
                    
        except urllib.error.HTTPError as e:
            self.logger.error(f"HTTP Error {e.code}: {e.reason}")
            return None
        except urllib.error.URLError as e:
            self.logger.error(f"URL Error: {e.reason}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error in HTTP request: {str(e)}")
            return None
    
    def _enrich_with_virustotal(self, ip, api_key, timeout, verify_ssl):
        """Query VirusTotal IP endpoint and return normalized enrichment data.

        Includes detection stats, reputation, network metadata, and optional top threats.
        """
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {
            "x-apikey": api_key,
            "User-Agent": "Cortex-IP-VirusTotal/2.0"
        }
        
        try:
            data = self._http_get_json(url, headers=headers, timeout=timeout, verify_ssl=verify_ssl)
            if not data:
                return None, "No response from VirusTotal"
            
            if "error" in data:
                return None, f"VirusTotal error: {data.get('error', {}).get('message', 'Unknown error')}"
            
            vt_data = data.get("data", {})
            if not isinstance(vt_data, dict):
                vt_data = {}
            attributes = vt_data.get("attributes", {})
            if not isinstance(attributes, dict):
                attributes = {}
            
            stats = attributes.get("last_analysis_stats", {})
            if not isinstance(stats, dict):
                stats = {}
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total_scans = sum(stats.values()) if stats else 0
            
            network = attributes.get("network", "Unknown")
            country = attributes.get("country", "Unknown")
            asn = attributes.get("asn")
            as_owner = attributes.get("as_owner", "Unknown")
            
            categories = attributes.get("categories", {})
            reputation = attributes.get("reputation", 0)
            
            if isinstance(categories, dict):
                category_list = list(categories.keys())
            elif isinstance(categories, list):
                category_list = [str(category) for category in categories]
            elif isinstance(categories, str):
                category_list = [categories]
            else:
                category_list = []

            whois_value = attributes.get("whois")
            if isinstance(whois_value, dict):
                whois_info = {
                    "registrar": whois_value.get("registrar"),
                    "creation_date": whois_value.get("creation_date"),
                    "updated_date": whois_value.get("updated_date")
                }
            elif isinstance(whois_value, str) and whois_value.strip():
                whois_info = {"raw": whois_value}
            else:
                whois_info = {}
            
            enrichment = {
                "source": "VirusTotal",
                "country": country,
                "network": network,
                "asn": asn,
                "as_owner": as_owner,
                "reputation_score": reputation,
                "detection_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "total_scans": total_scans,
                    "detection_ratio": f"{malicious + suspicious}/{total_scans}" if total_scans > 0 else "0/0"
                },
                "categories": category_list,
                "reputation": "malicious" if malicious > 3 else "suspicious" if suspicious > 2 or malicious > 0 else "clean",
                "last_analysis_date": datetime.fromtimestamp(attributes.get("last_analysis_date", 0)).isoformat() if attributes.get("last_analysis_date") else None,
                "whois_info": whois_info,
                "tags": attributes.get("tags", []),
                "raw": data
            }
            
            if malicious > 0:
                scan_results = attributes.get("last_analysis_results", {})
                if not isinstance(scan_results, dict):
                    scan_results = {}
                malicious_engines = [(engine, result["result"]) for engine, result in scan_results.items() 
                               if isinstance(result, dict) and result.get("category") == "malicious" and result.get("result")]
                enrichment["top_threats"] = malicious_engines[:10]  # Top 10 detections
            
            self.logger.info(f"VirusTotal enrichment successful for {ip}")
            return enrichment, None
            
        except Exception as e:
            error_msg = f"VirusTotal request failed: {str(e)}"
            self.logger.error(error_msg)
            return None, error_msg

    def run(self):
        """Analyzer entrypoint.

        Reads input/config, validates IP, optionally skips non-public ranges,
        fetches VirusTotal enrichment, then reports the result to Cortex.
        """
        try:
            ip = self.get_param('data', None, 'Missing IP')
            
            api_key = self.get_param('config.api_key', None, 'VirusTotal API key is required')
            timeout = self.get_param('config.api_timeout', 10)
            verify_ssl = self.get_param('config.enable_ssl_verify', True)
            skip_private = self.get_param('config.skip_private_ips', True)
            
            valid, ip_obj, is_public = self._validate_ip(ip)
            
            if not valid:
                self.report({
                    "ip": ip, 
                    "valid": False,
                    "error": "Invalid IP format",
                    "message": "The provided input is not a valid IP address"
                })
                return
            
            if not is_public and skip_private:
                ip_type = "private" if ip_obj.is_private else "reserved"
                if ip_obj.is_loopback:
                    ip_type = "loopback"
                elif ip_obj.is_multicast:
                    ip_type = "multicast"
                elif ip_obj.is_link_local:
                    ip_type = "link-local"
                
                self.report({
                    "ip": ip,
                    "valid": True,
                    "public": False,
                    "ip_type": ip_type,
                    "message": f"{ip_type.title()} IP address - enrichment skipped",
                    "enrichment_skipped": True
                })
                return
            
            self.logger.info(f"Processing public IP: {ip}")
            
            report = {
                "ip": ip,
                "valid": True,
                "public": is_public,
                "resolvable": self._is_resolvable(ip)
            }
            
            enrichment, error = self._enrich_with_virustotal(ip, api_key, timeout, verify_ssl)
            
            if enrichment:
                report.update(enrichment)
                enrichment_success = True
                self.logger.info(f"IP analysis completed: {enrichment['reputation']} ({enrichment['detection_stats']['detection_ratio']} detections)")
            else:
                report["enrichment_failed"] = True
                report["message"] = "Failed to enrich IP from VirusTotal"
                report["error"] = error
                enrichment_success = False
            
            self.logger.info(f"IP enrichment completed for {ip}. Success: {enrichment_success}")
            self.report(report)
            
        except Exception as e:
            self.logger.error(f"Unexpected error in analyzer: {str(e)}")
            self.unexpectedError(str(e))

    def summary(self, raw):
        """Build a concise Cortex summary from enrichment output."""
        try:
            valid = raw.get("valid", False)
            public = raw.get("public", False)
            
            if not valid:
                return {
                    "Valid": valid,
                    "Error": "Invalid IP format"
                }
            
            if not public:
                return {
                    "Valid": valid,
                    "Public": public,
                    "Type": raw.get("ip_type", "Private")
                }
            
            if raw.get("enrichment_failed"):
                return {
                    "Valid": valid,
                    "Public": public,
                    "Error": "VirusTotal enrichment failed"
                }
            
            country = raw.get("country", "Unknown")
            as_owner = raw.get("as_owner", "Unknown")
            reputation = raw.get("reputation", "Unknown")
            stats = raw.get("detection_stats", {})
            detection_ratio = stats.get("detection_ratio", "0/0")
            
            summary = {
                "Valid": valid,
                "Public": public,
                "Country": country,
                "AS Owner": as_owner,
                "Reputation": reputation,
                "Detections": detection_ratio
            }
            
            # Add threat categories if available
            categories = raw.get("categories", [])
            if categories:
                summary["Categories"] = ", ".join(categories[:3])  # Top 3 categories
            
            # Add threat names for malicious IPs
            if raw.get("top_threats"):
                threats = [threat[1] for threat in raw["top_threats"][:3]]  # Top 3 threats
                summary["Top Threats"] = ", ".join(threats)
                
            return summary
            
        except Exception as e:
            self.logger.error(f"Error generating summary: {str(e)}")
            return {"Error": "Failed to generate summary"}

if __name__ == "__main__":
    IPEnrichVirusTotal().run()
