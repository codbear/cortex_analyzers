#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cortex analyzer to enrich file hashes with VirusTotal v3."""

from cortexutils.analyzer import Analyzer
import json
import re
import urllib.request
import urllib.error
import ssl
import logging
from datetime import datetime

class HashEnrichVirusTotal(Analyzer):
    """Look up MD5/SHA1/SHA256 hashes and return normalized threat data."""
    
    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(self.__class__.__name__)
        
        self.HASH_PATTERNS = {
            "md5": r"[a-f0-9]{32}",
            "sha1": r"[a-f0-9]{40}", 
            "sha256": r"[a-f0-9]{64}"
        }
    
    def _validate_hash(self, h):
        """Validate hash format and return `(is_valid, hash_type)`.

        Only lowercase hexadecimal MD5/SHA1/SHA256 formats are accepted.
        """
        if not h or not isinstance(h, str):
            return False, "unknown"
        
        h = h.strip().lower()
        
        if re.search(r'[^a-f0-9]', h):
            self.logger.warning(f"Invalid characters in hash: {h}")
            return False, "unknown"
        
        for hash_type, pattern in self.HASH_PATTERNS.items():
            if re.fullmatch(pattern, h):
                return True, hash_type
        
        return False, "unknown"
    
    def _detect_hash_type(self, h):
        """Backward-compatible wrapper returning only the detected hash type."""
        valid, hash_type = self._validate_hash(h)
        return hash_type

    def _http_get_json(self, url, headers=None, timeout=15, verify_ssl=True):
        """Execute HTTP GET and return a parsed JSON object or `None`.

        Handles SSL options, empty responses, and JSON decoding errors.
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
                    
                body = r.read().decode("utf-8", errors="replace").strip()
                
                if body in ("", "null"):
                    self.logger.info("API returned empty response")
                    return None
                
                try:
                    return json.loads(body)
                except json.JSONDecodeError as e:
                    self.logger.error(f"Failed to parse JSON response: {e}")
                    return None
                    
        except urllib.error.HTTPError as e:
            self.logger.error(f"HTTP Error {e.code}: {e.reason}")
            if e.code == 404:
                return None  # Hash not found, this is normal
            raise
        except urllib.error.URLError as e:
            self.logger.error(f"URL Error: {e.reason}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error in HTTP request: {str(e)}")
            raise

    def run(self):
        """Analyzer entrypoint.

        Reads input/config, validates hash, queries VirusTotal, and reports a
        normalized enrichment payload with detection statistics.
        """
        try:
            h = self.get_param('data', None, 'Missing hash')
            
            api_key = self.get_param('config.api_key', None, 'VirusTotal API key is required')
            timeout = self.get_param('config.api_timeout', 15)
            verify_ssl = self.get_param('config.enable_ssl_verify', True)
            
            valid, htype = self._validate_hash(h)
            
            if not valid or htype == "unknown":
                self.report({
                    "hash": h,
                    "valid": False,
                    "hash_type": htype,
                    "message": "Unsupported hash format (expected MD5/SHA1/SHA256) or invalid characters",
                    "supported_types": list(self.HASH_PATTERNS.keys())
                })
                return
            
            h = h.strip().lower()
            
            self.logger.info(f"Processing {htype.upper()} hash: {h}")
            
            url = f"https://www.virustotal.com/api/v3/files/{h}"
            headers = {
                "x-apikey": api_key,
                "User-Agent": "Cortex-Hash-VirusTotal/2.0"
            }
            
            try:
                data = self._http_get_json(url, headers=headers, timeout=timeout, verify_ssl=verify_ssl)

                if not data:
                    self.report({
                        "hash": h,
                        "hash_type": htype,
                        "found": False,
                        "source": "VirusTotal",
                        "message": "Hash not found in VirusTotal database"
                    })
                    return

                attributes = data.get("data", {}).get("attributes", {})
                
                stats = attributes.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total_scans = sum(stats.values()) if stats else 0
                
                file_info = {
                    "size": attributes.get("size"),
                    "type_description": attributes.get("type_description"),
                    "magic": attributes.get("magic"),
                    "md5": attributes.get("md5"),
                    "sha1": attributes.get("sha1"),
                    "sha256": attributes.get("sha256"),
                    "ssdeep": attributes.get("ssdeep"),
                    "tlsh": attributes.get("tlsh")
                }
                
                names = attributes.get("meaningful_name", attributes.get("names", []))
                if isinstance(names, list) and names:
                    filename = names[0]
                else:
                    filename = names if isinstance(names, str) else "Unknown"
                
                report = {
                    "hash": h,
                    "hash_type": htype,
                    "found": True,
                    "source": "VirusTotal",
                    "filename": filename,
                    "file_info": file_info,
                    "detection_stats": {
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "harmless": stats.get("harmless", 0),
                        "undetected": stats.get("undetected", 0),
                        "total_scans": total_scans,
                        "detection_ratio": f"{malicious + suspicious}/{total_scans}" if total_scans > 0 else "0/0"
                    },
                    "reputation": "malicious" if malicious > 5 else "suspicious" if suspicious > 3 or malicious > 0 else "clean",
                    "first_submission_date": datetime.fromtimestamp(attributes.get("first_submission_date", 0)).isoformat() if attributes.get("first_submission_date") else None,
                    "last_analysis_date": datetime.fromtimestamp(attributes.get("last_analysis_date", 0)).isoformat() if attributes.get("last_analysis_date") else None,
                    "tags": attributes.get("tags", []),
                    "crowdsourced_yara_rules": len(attributes.get("crowdsourced_yara_results", [])),
                    "sandbox_verdicts": attributes.get("sandbox_verdicts", {}),
                    "raw": data
                }
                
                if malicious > 0:
                    scan_results = attributes.get("last_analysis_results", {})
                    malicious_engines = [(engine, result["result"]) for engine, result in scan_results.items() 
                                       if result.get("category") == "malicious" and result.get("result")]
                    report["top_threats"] = malicious_engines[:10]  # Top 10 detections
                
                self.logger.info(f"Hash analysis completed: {report['reputation']} ({malicious}/{total_scans} detections)")
                self.report(report)

            except urllib.error.HTTPError as e:
                if e.code == 404:
                    self.report({
                        "hash": h,
                        "hash_type": htype,
                        "found": False,
                        "source": "VirusTotal",
                        "message": "Hash not found in VirusTotal database"
                    })
                else:
                    self.report({
                        "hash": h,
                        "hash_type": htype,
                        "found": False,
                        "source": "VirusTotal",
                        "error": f"HTTP Error {e.code}: {e.reason}",
                        "message": "API request failed"
                    })
            except urllib.error.URLError as e:
                self.report({
                    "hash": h,
                    "hash_type": htype,
                    "found": False,
                    "source": "VirusTotal",
                    "error": f"Network Error: {getattr(e, 'reason', str(e))}",
                    "message": "Failed to connect to VirusTotal API"
                })
            except Exception as e:
                self.logger.error(f"Unexpected error during API call: {str(e)}")
                self.report({
                    "hash": h,
                    "hash_type": htype,
                    "found": False,
                    "source": "VirusTotal",
                    "error": f"Unexpected error: {str(e)}",
                    "message": "Internal error during hash lookup"
                })
                
        except Exception as e:
            self.logger.error(f"Unexpected error in analyzer: {str(e)}")
            self.unexpectedError(str(e))

    def summary(self, raw):
        """Return a compact Cortex summary from the full enrichment payload."""
        try:
            found = raw.get("found", False)
            
            if not found:
                return {
                    "Found": found,
                    "Error": raw.get("message", "Hash not found")
                }
            
            filename = raw.get("filename", "Unknown")
            reputation = raw.get("reputation", "Unknown")
            stats = raw.get("detection_stats", {})
            detection_ratio = stats.get("detection_ratio", "0/0")
            
            summary = {
                "Found": found,
                "Filename": filename,
                "Reputation": reputation,
                "Detections": detection_ratio
            }
            
            # Add file type if available
            file_info = raw.get("file_info", {})
            if file_info.get("type_description"):
                summary["Type"] = file_info["type_description"]
            
            # Add threat names for malicious files
            if raw.get("top_threats"):
                threats = [threat[1] for threat in raw["top_threats"][:3]]  # Top 3 threats
                summary["Top Threats"] = ", ".join(threats)
                
            return summary
            
        except Exception as e:
            self.logger.error(f"Error generating summary: {str(e)}")
            return {"Error": "Failed to generate summary"}

if __name__ == "__main__":
    HashEnrichVirusTotal().run()
