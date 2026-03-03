#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cortex analyzer for LDAP machine/host lookups."""

from cortexutils.analyzer import Analyzer
import subprocess
import re
import logging

class LDAPMachineAnalyzer(Analyzer):
    """Search an LDAP directory for a machine and return normalized attributes."""
    
    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(self.__class__.__name__)
        
        self.LDAP_ATTRIBUTES = {
            'cn': 'cn',
            'uid': 'uid', 
            'description': 'description'
        }
    
    def _validate_hostname(self, hostname):
        """Validate hostname format and length before LDAP search."""
        if not hostname:
            return False
        
        # Allow alphanumeric, hyphens, dots, and underscores
        # Reject if contains spaces or special characters that could be used for injection
        pattern = r'^[a-zA-Z0-9._-]+$'
        if not re.match(pattern, hostname):
            self.logger.warning(f"Invalid hostname format: {hostname}")
            return False
        
        if len(hostname) > 253:  # RFC 1035 limit
            self.logger.warning(f"Hostname too long: {hostname}")
            return False
            
        return True

    def _run_ldapsearch(self, ldap_uri, bind_dn, bind_pw, base_dn, ldap_filter, timeout=30):
        """Run `ldapsearch` and return `(return_code, stdout)`.

        Uses argument lists, timeout protection, and safe logging behavior.
        """
        cmd = [
            "ldapsearch",
            "-x",  # Simple authentication
            "-H", ldap_uri,
            "-D", bind_dn,
            "-w", bind_pw,
            "-b", base_dn,
            "-o", f"nettimeout={timeout}",  # Network timeout
            "-o", f"ldif-wrap=no",  # Disable line wrapping
            ldap_filter
        ]
        
        try:
            self.logger.info(f"Executing LDAP search for filter: {ldap_filter}")
            p = subprocess.run(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True,
                timeout=timeout + 10  # subprocess timeout slightly higher than LDAP timeout
            )
            
            if p.returncode != 0:
                self.logger.error(f"LDAP search failed with return code {p.returncode}: {p.stderr}")
            
            return p.returncode, p.stdout
            
        except subprocess.TimeoutExpired:
            self.logger.error(f"LDAP search timed out after {timeout} seconds")
            return 1, "Timeout: LDAP search exceeded time limit"
        except Exception as e:
            self.logger.error(f"Error executing LDAP search: {str(e)}")
            return 1, f"Error: {str(e)}"

    def _parse_ldap_output(self, output):
        """Parse LDIF output into a normalized dictionary.

        Missing values keep the default `"Not found"` value.
        """
        result = {
            "found": False,
            "cn": "Not found",
            "uid": "Not found", 
            "description": "Not found",
            "ou": "Not found"
        }
        
        try:
            if not output or "\ndn:" not in ("\n" + output):
                return result
            
            result["found"] = True
            
            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue
                    
                for ldap_attr, result_key in self.LDAP_ATTRIBUTES.items():
                    if line.startswith(f"{ldap_attr}:"):
                        value = line.split(":", 1)[1].strip()
                        result[result_key] = value
                        break
                
                if line.startswith("dn:"):
                    dn = line.split(":", 1)[1].strip()
                    ou_parts = [p.strip() for p in dn.split(",") 
                               if p.strip().lower().startswith("ou=")]
                    result["ou"] = ", ".join(ou_parts) if ou_parts else "Not found"
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error parsing LDAP output: {str(e)}")
            return result

    def run(self):
        """Analyzer entrypoint.

        Reads input/config, validates hostname, runs LDAP query, parses output,
        and reports normalized machine data to Cortex.
        """
        try:
            hostname = self.get_param('data', None, 'Missing hostname')
            
            if not self._validate_hostname(hostname):
                self.error("Invalid hostname format")
                return
            
            ldap_uri = self.get_param('config.ldap_uri', None, 'LDAP URI not configured')
            bind_dn = self.get_param('config.bind_dn', None, 'LDAP bind DN not configured')
            bind_pw = self.get_param('config.bind_password', None, 'LDAP bind password not configured')
            base_dn = self.get_param('config.base_dn', None, 'LDAP base DN not configured')
            timeout = self.get_param('config.timeout', 30)
            
            self.logger.info(f"Searching for machine: {hostname}")
            
            ldap_filter = f"(cn={hostname})"
            
            rc, output = self._run_ldapsearch(ldap_uri, bind_dn, bind_pw, base_dn, ldap_filter, timeout)
            
            if rc != 0:
                # Determine specific error type
                if "Invalid credentials" in output:
                    self.error("LDAP authentication failed - check bind credentials")
                elif "Can't contact LDAP server" in output:
                    self.error("Cannot connect to LDAP server - check URI and network")
                elif "Timeout" in output:
                    self.error("LDAP search timed out - server may be overloaded")
                else:
                    self.error(f"LDAP search failed: {output}")
                return
            
            result = self._parse_ldap_output(output)
            
            result.update({
                "hostname": hostname,
                "base_dn": base_dn,
                "filter": ldap_filter,
                "ldap_server": ldap_uri
            })
            
            if not result["found"]:
                result["message"] = f"Machine '{hostname}' not found in LDAP directory"
                self.logger.info(f"Machine not found: {hostname}")
            else:
                self.logger.info(f"Machine found: {hostname} -> {result['cn']}")
            
            self.report(result)
            
        except Exception as e:
            self.logger.error(f"Unexpected error in analyzer: {str(e)}")
            self.unexpectedError(str(e))

    def summary(self, raw):
        """Build a compact Cortex summary for quick analyst triage."""
        try:
            found = raw.get("found", False)
            machine = raw.get("cn", "Unknown")
            description = raw.get("description", "Unknown")
            
            summary = {
                "Found": found,
                "Machine": machine,
                "Description": description
            }
            
            if not found:
                summary["Error"] = raw.get("message", "Machine not found")
                
            return summary
            
        except Exception as e:
            self.logger.error(f"Error generating summary: {str(e)}")
            return {"Error": "Failed to generate summary"}
    
if __name__ == "__main__":
    LDAPMachineAnalyzer().run()
