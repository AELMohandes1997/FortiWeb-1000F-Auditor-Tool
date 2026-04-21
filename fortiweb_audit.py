#!/usr/bin/env python3
"""
FortiWeb 1000F Configuration Audit Script
==========================================
Benchmark: FortiWeb Hardening Guide + CIS Principles
Author   : Security Assessment Team
Usage    : python3 fortiweb_audit.py <config_file.conf> [--output report.html] [--format html|csv|text]

This script parses the FortiWeb .conf file, maps each configuration block to
benchmark controls, and outputs a colour-coded audit report.
"""

import re
import sys
import os
import json
import argparse
from datetime import datetime
from collections import defaultdict


# ─────────────────────────────────────────────────────────────────────────────
# PARSER — FortiWeb .conf structure reader
# FortiWeb config format:
#   config <section>
#       edit <name>
#           set <key> <value>
#       next
#   end
# ─────────────────────────────────────────────────────────────────────────────

class FortiWebConfigParser:
    def __init__(self, filepath):
        self.filepath = filepath
        self.raw_text = ""
        self.config_tree = defaultdict(lambda: defaultdict(dict))
        self.flat_config = {}   # "section::key" -> value
        self.global_settings = {}

    def load(self):
        try:
            with open(self.filepath, 'r', encoding='utf-8', errors='ignore') as f:
                self.raw_text = f.read()
        except FileNotFoundError:
            print(f"[ERROR] Config file not found: {self.filepath}")
            sys.exit(1)
        self._parse()

    def _parse(self):
        """
        Walk the config line by line, building a nested dict:
        config_tree[section][entry_name][key] = value
        For top-level (no edit) sections: config_tree[section]['__global__'][key] = value
        """
        lines = self.raw_text.splitlines()
        section_stack = []
        current_entry = None

        i = 0
        while i < len(lines):
            line = lines[i].strip()

            if not line or line.startswith('#'):
                i += 1
                continue

            if line.startswith('config '):
                section = line[7:].strip()
                section_stack.append(section)
                current_entry = '__global__'

            elif line == 'end':
                if section_stack:
                    section_stack.pop()
                current_entry = '__global__'

            elif line.startswith('edit '):
                current_entry = line[5:].strip().strip('"')

            elif line == 'next':
                current_entry = '__global__'

            elif line.startswith('set '):
                parts = line[4:].split(None, 1)
                if len(parts) >= 1:
                    key = parts[0]
                    value = parts[1].strip('"') if len(parts) > 1 else ''
                    if section_stack:
                        full_section = ' > '.join(section_stack)
                        if current_entry is None:
                            current_entry = '__global__'
                        self.config_tree[full_section][current_entry][key] = value
                        flat_key = f"{full_section}::{current_entry}::{key}"
                        self.flat_config[flat_key] = value

            i += 1

    def get_section(self, section_path):
        """Return all entries under a section path (partial match supported)."""
        results = {}
        for key, val in self.config_tree.items():
            if section_path.lower() in key.lower():
                results[key] = val
        return results

    def get_global_value(self, section_path, key):
        """Get a single global (non-edit) value from a section."""
        for skey, entries in self.config_tree.items():
            if section_path.lower() in skey.lower():
                global_entry = entries.get('__global__', {})
                if key in global_entry:
                    return global_entry[key]
        return None

    def get_all_entries(self, section_path):
        """Return all named entries (from edit blocks) in a section."""
        entries = {}
        for skey, val in self.config_tree.items():
            if section_path.lower() in skey.lower():
                for ename, edata in val.items():
                    if ename != '__global__':
                        entries[ename] = edata
        return entries

    def raw_search(self, pattern):
        """Regex search directly on raw config text. Returns list of matches."""
        return re.findall(pattern, self.raw_text, re.IGNORECASE | re.MULTILINE)

    def section_exists(self, section_path):
        """Check if a config section exists at all."""
        for key in self.config_tree.keys():
            if section_path.lower() in key.lower():
                return True
        return False


# ─────────────────────────────────────────────────────────────────────────────
# RESULT MODEL
# ─────────────────────────────────────────────────────────────────────────────

class CheckResult:
    PASS   = "PASS"
    FAIL   = "FAIL"
    WARN   = "WARN"
    INFO   = "INFO"
    SKIP   = "SKIP"   # Could not determine from config

    def __init__(self, control_id, title, severity, status, finding, recommendation, config_path, actual_value=None):
        self.control_id     = control_id
        self.title          = title
        self.severity       = severity
        self.status         = status
        self.finding        = finding
        self.recommendation = recommendation
        self.config_path    = config_path
        self.actual_value   = actual_value


# ─────────────────────────────────────────────────────────────────────────────
# AUDIT ENGINE — ALL BENCHMARK CHECKS
# ─────────────────────────────────────────────────────────────────────────────

class FortiWebAuditor:
    def __init__(self, parser: FortiWebConfigParser):
        self.cfg = parser
        self.results = []

    def run_all(self):
        print("[*] Starting FortiWeb 1000F Configuration Audit...")
        self._section1_system_hardening()
        self._section2_network_interfaces()
        self._section3_logging()
        self._section4_waf_policy()
        self._section5_ssl_tls()
        self._section6_access_control()
        self._section7_authentication()
        self._section8_security_headers()
        self._section9_advanced_threats()
        self._section10_ha()
        self._section11_backup()
        print(f"[*] Audit complete. {len(self.results)} controls evaluated.")
        return self.results

    def _add(self, cid, title, severity, status, finding, rec, path, actual=None):
        self.results.append(CheckResult(cid, title, severity, status, finding, rec, path, actual))

    # ── HELPERS ──────────────────────────────────────────────────────────────

    def _val(self, section, key, entry='__global__'):
        """Shortcut to get a value."""
        for skey, entries in self.cfg.config_tree.items():
            if section.lower() in skey.lower():
                ev = entries.get(entry, {})
                if key in ev:
                    return ev[key]
        return None

    def _global(self, section, key):
        return self.cfg.get_global_value(section, key)

    def _entries(self, section):
        return self.cfg.get_all_entries(section)

    def _exists(self, section):
        return self.cfg.section_exists(section)

    # ════════════════════════════════════════════════════════════════════════
    # SECTION 1 — SYSTEM HARDENING
    # ════════════════════════════════════════════════════════════════════════

    def _section1_system_hardening(self):
        print("[*] Section 1: System Hardening")

        # 1.1.1 Default admin account renamed
        admins = self._entries('system admin')
        if 'admin' in admins:
            self._add('1.1.1', 'Default admin account renamed', 'CRITICAL', CheckResult.FAIL,
                'Account named "admin" still exists. Default account names are trivially targeted.',
                'Rename default admin account to a non-obvious name. Delete if unused.',
                'config system admin', actual='admin account found')
        elif admins:
            self._add('1.1.1', 'Default admin account renamed', 'CRITICAL', CheckResult.PASS,
                'No account named "admin" found.',
                '', 'config system admin', actual=f'Accounts: {list(admins.keys())}')
        else:
            self._add('1.1.1', 'Default admin account renamed', 'CRITICAL', CheckResult.SKIP,
                'No admin accounts found in config — section may be absent.',
                'Verify admin configuration is present in config file.',
                'config system admin')

        # 1.1.2 / 1.1.3 Password policy
        min_len = self._global('system password-policy', 'min-length')
        if min_len is None:
            min_len = self._global('system password-policy', 'minimum-length')
        if min_len:
            actual = int(min_len) if min_len.isdigit() else 0
            status = CheckResult.PASS if actual >= 8 else CheckResult.FAIL
            self._add('1.1.3', 'Admin password minimum length >= 8', 'HIGH', status,
                f'min-length = {min_len}',
                'Set minimum password length to at least 8 (recommend 12+).',
                'config system password-policy', actual=min_len)
        else:
            self._add('1.1.3', 'Admin password minimum length >= 8', 'HIGH', CheckResult.SKIP,
                'Password policy section not found or min-length not set.',
                'Configure: config system password-policy > set min-length 12',
                'config system password-policy')

        # 1.1.4 Password expiry
        expire = self._global('system password-policy', 'expire-day')
        if expire:
            actual = int(expire) if expire.isdigit() else 9999
            status = CheckResult.PASS if actual <= 90 else CheckResult.WARN
            self._add('1.1.4', 'Password expiry <= 90 days', 'MEDIUM', status,
                f'expire-day = {expire}',
                'Set expire-day to 90 or less.',
                'config system password-policy', actual=expire)
        else:
            self._add('1.1.4', 'Password expiry configured', 'MEDIUM', CheckResult.SKIP,
                'expire-day not found in password-policy.',
                'Configure password expiry: set expire-day 90',
                'config system password-policy')

        # 1.1.5 Account lockout threshold
        lockout = self._global('system password-policy', 'lockout-threshold')
        if lockout:
            actual = int(lockout) if lockout.isdigit() else 9999
            status = CheckResult.PASS if actual <= 5 else CheckResult.FAIL
            self._add('1.1.5', 'Account lockout threshold <= 5 attempts', 'HIGH', status,
                f'lockout-threshold = {lockout}',
                'Set lockout-threshold to 5 or fewer failed attempts.',
                'config system password-policy', actual=lockout)
        else:
            self._add('1.1.5', 'Account lockout threshold configured', 'HIGH', CheckResult.SKIP,
                'lockout-threshold not found.',
                'Configure: set lockout-threshold 5',
                'config system password-policy')

        # 1.1.6 Lockout duration
        duration = self._global('system password-policy', 'lockout-duration')
        if duration:
            actual = int(duration) if duration.isdigit() else 0
            status = CheckResult.PASS if actual >= 300 else CheckResult.FAIL
            self._add('1.1.6', 'Lockout duration >= 300 seconds', 'MEDIUM', status,
                f'lockout-duration = {duration}',
                'Set lockout-duration to at least 300 seconds (5 minutes).',
                'config system password-policy', actual=duration)
        else:
            self._add('1.1.6', 'Lockout duration configured', 'MEDIUM', CheckResult.SKIP,
                'lockout-duration not found.',
                'Configure: set lockout-duration 300',
                'config system password-policy')

        # 1.1.7 Two-factor auth (check on each admin account)
        for aname, adata in admins.items():
            tfa = adata.get('two-factor', 'disable')
            status = CheckResult.PASS if tfa == 'enable' else CheckResult.FAIL
            self._add('1.1.7', f'Two-factor auth enabled [{aname}]', 'HIGH', status,
                f'Admin "{aname}": two-factor = {tfa}',
                f'Enable two-factor auth for admin "{aname}": set two-factor enable',
                'config system admin', actual=tfa)

        # 1.1.8 Idle timeout
        idle = self._global('system global', 'idle-timeout')
        if idle:
            actual = int(idle) if idle.isdigit() else 9999
            status = CheckResult.PASS if actual <= 300 else CheckResult.WARN
            self._add('1.1.8', 'Admin idle session timeout <= 300s', 'MEDIUM', status,
                f'idle-timeout = {idle} seconds',
                'Set idle-timeout to 300 seconds or less.',
                'config system global', actual=idle)
        else:
            self._add('1.1.8', 'Admin idle session timeout configured', 'MEDIUM', CheckResult.SKIP,
                'idle-timeout not found in system global.',
                'Configure: set idle-timeout 300',
                'config system global')

        # 1.1.9 / 1.1.10 Trusted hosts
        for aname, adata in admins.items():
            has_trusthost = any(k.startswith('trusthost') for k in adata.keys())
            wildcard = any(
                v in ['0.0.0.0 0.0.0.0', '0.0.0.0/0', '::/0']
                for k, v in adata.items() if k.startswith('trusthost')
            )
            if wildcard:
                self._add('1.1.10', f'No wildcard trusted host [{aname}]', 'CRITICAL', CheckResult.FAIL,
                    f'Admin "{aname}" has trusthost = 0.0.0.0/0 — unrestricted admin access!',
                    f'Restrict trusthost for "{aname}" to the management network only.',
                    'config system admin', actual='0.0.0.0 0.0.0.0')
            elif has_trusthost:
                self._add('1.1.9', f'Trusted hosts configured [{aname}]', 'CRITICAL', CheckResult.PASS,
                    f'Admin "{aname}" has trusthost restrictions defined.',
                    '', 'config system admin')
            else:
                self._add('1.1.9', f'Trusted hosts configured [{aname}]', 'CRITICAL', CheckResult.FAIL,
                    f'Admin "{aname}" has NO trusthost defined — accessible from any IP.',
                    f'Configure trusthost1/2/3 for "{aname}" to restrict management access.',
                    'config system admin')

        # 1.2.1 HTTPS only
        http_en  = self._global('system global', 'admin-http')
        https_en = self._global('system global', 'admin-https')
        if http_en is not None:
            status = CheckResult.PASS if http_en == 'disable' else CheckResult.FAIL
            self._add('1.2.1', 'HTTP management access disabled', 'CRITICAL', status,
                f'admin-http = {http_en}',
                'Disable HTTP management: set admin-http disable',
                'config system global', actual=http_en)
        else:
            self._add('1.2.1', 'HTTP management access disabled', 'CRITICAL', CheckResult.SKIP,
                'admin-http not found in system global.',
                'Ensure admin-http is explicitly disabled.',
                'config system global')

        # 1.2.4 Telnet disabled
        telnet = self._global('system global', 'admin-telnet')
        if telnet is not None:
            status = CheckResult.PASS if telnet == 'disable' else CheckResult.FAIL
            self._add('1.2.4', 'Telnet management disabled', 'CRITICAL', status,
                f'admin-telnet = {telnet}',
                'Disable Telnet: set admin-telnet disable',
                'config system global', actual=telnet)
        else:
            # Telnet not set usually means disabled by default — note it
            self._add('1.2.4', 'Telnet management disabled', 'CRITICAL', CheckResult.INFO,
                'admin-telnet not found in config — likely disabled by default. Verify on device.',
                'Explicitly set: set admin-telnet disable',
                'config system global')

        # 1.2.5 SNMP communities — check for v1/v2 and default strings
        snmp_communities = self._entries('system snmp community')
        for cname, cdata in snmp_communities.items():
            version = cdata.get('status', '')
            query_v1 = cdata.get('query-v1-status', 'enable')
            query_v2 = cdata.get('query-v2c-status', 'enable')
            trap_v1  = cdata.get('trap-v1-status', 'enable')
            trap_v2  = cdata.get('trap-v2c-status', 'enable')

            if query_v1 == 'enable' or trap_v1 == 'enable':
                self._add('1.2.5', f'SNMP v1 disabled [{cname}]', 'HIGH', CheckResult.FAIL,
                    f'Community "{cname}" has SNMPv1 enabled.',
                    'Disable SNMPv1: set query-v1-status disable, set trap-v1-status disable',
                    'config system snmp community', actual='v1 enabled')

            if cname.lower() in ['public', 'private']:
                self._add('1.2.7', f'SNMP default community string [{cname}]', 'CRITICAL', CheckResult.FAIL,
                    f'Default SNMP community string "{cname}" in use.',
                    'Delete default community and create with a strong, unique name.',
                    'config system snmp community', actual=cname)

        if not snmp_communities:
            self._add('1.2.5', 'SNMP community configuration', 'HIGH', CheckResult.INFO,
                'No SNMP communities found in config. SNMP may be disabled.',
                'Verify SNMP is intentionally disabled or configure v3 only.',
                'config system snmp community')

        # 1.3.1 NTP
        ntp_sync = self._global('system ntp', 'ntpsync')
        ntp_server = self._global('system ntp', 'server')
        if ntp_sync == 'enable' and ntp_server:
            self._add('1.3.1', 'NTP server configured and enabled', 'HIGH', CheckResult.PASS,
                f'NTP sync enabled, server = {ntp_server}',
                '', 'config system ntp', actual=ntp_server)
        elif ntp_sync == 'enable' and not ntp_server:
            self._add('1.3.1', 'NTP server configured and enabled', 'HIGH', CheckResult.FAIL,
                'ntpsync = enable but no NTP server defined.',
                'Configure NTP server: set server <ntp-server-ip>',
                'config system ntp')
        else:
            self._add('1.3.1', 'NTP server configured and enabled', 'HIGH', CheckResult.FAIL,
                f'NTP sync disabled or not configured. ntpsync = {ntp_sync}',
                'Enable NTP: set ntpsync enable, set server <ip>',
                'config system ntp', actual=ntp_sync)

        # 1.3.4 Hostname not default
        hostname = self._global('system global', 'hostname')
        if hostname and hostname.lower() not in ['fortiweb', 'fortiweb-1000f', '']:
            self._add('1.3.4', 'Hostname configured (not default)', 'LOW', CheckResult.PASS,
                f'Hostname = {hostname}', '', 'config system global', actual=hostname)
        else:
            self._add('1.3.4', 'Hostname configured (not default)', 'LOW', CheckResult.WARN,
                f'Hostname = "{hostname}" — appears to be default or not set.',
                'Set a meaningful hostname: set hostname <device-name>',
                'config system global', actual=hostname)

    # ════════════════════════════════════════════════════════════════════════
    # SECTION 2 — NETWORK & INTERFACES
    # ════════════════════════════════════════════════════════════════════════

    def _section2_network_interfaces(self):
        print("[*] Section 2: Network & Interfaces")

        interfaces = self._entries('system interface')
        for iname, idata in interfaces.items():
            itype   = idata.get('type', '')
            status  = idata.get('status', 'up')
            ip      = idata.get('ip', '')
            role    = idata.get('role', '')

            # 2.1.1 Unused interfaces down
            if status == 'up' and not ip and itype == 'physical':
                self._add('2.1.1', f'Unused interface disabled [{iname}]', 'MEDIUM', CheckResult.WARN,
                    f'Interface {iname} is UP but has no IP assigned — may be unused.',
                    f'Disable if unused: config system interface > edit {iname} > set status down',
                    'config system interface', actual=f'status={status}, ip={ip}')

        # 2.2.1 Default route
        static_routes = self._entries('router static')
        has_default = any(
            r.get('dst', '') in ['0.0.0.0 0.0.0.0', '0.0.0.0/0']
            for r in static_routes.values()
        )
        if has_default:
            self._add('2.2.1', 'Default route defined', 'HIGH', CheckResult.PASS,
                'Default route (0.0.0.0/0) found in routing table.',
                '', 'config router static')
        else:
            self._add('2.2.1', 'Default route defined', 'HIGH', CheckResult.WARN,
                'No default route found in config.',
                'Configure a default route to the upstream gateway.',
                'config router static')

    # ════════════════════════════════════════════════════════════════════════
    # SECTION 3 — LOGGING & ALERTING
    # ════════════════════════════════════════════════════════════════════════

    def _section3_logging(self):
        print("[*] Section 3: Logging & Alerting")

        # 3.1.1/3.1.2 Syslog server
        syslog_status  = self._global('log syslogd setting', 'status')
        syslog_server  = self._global('log syslogd setting', 'server')
        syslog_mode    = self._global('log syslogd setting', 'mode')

        if syslog_status == 'enable' and syslog_server:
            self._add('3.1.1', 'Syslog server configured', 'CRITICAL', CheckResult.PASS,
                f'Syslog enabled, server = {syslog_server}',
                '', 'config log syslogd setting', actual=syslog_server)
        elif syslog_status == 'enable' and not syslog_server:
            self._add('3.1.1', 'Syslog server configured', 'CRITICAL', CheckResult.FAIL,
                'Syslog is enabled but no server IP is defined.',
                'Set syslog server: set server <siem-ip>',
                'config log syslogd setting')
        else:
            self._add('3.1.1', 'Syslog server configured', 'CRITICAL', CheckResult.FAIL,
                f'Syslog not enabled or not configured. status = {syslog_status}',
                'Enable syslog: set status enable, set server <siem-ip>',
                'config log syslogd setting', actual=syslog_status)

        # 3.1.10 Reliable syslog (TCP)
        if syslog_mode:
            status = CheckResult.PASS if syslog_mode == 'reliable' else CheckResult.WARN
            self._add('3.1.10', 'Syslog reliable mode (TCP)', 'MEDIUM', status,
                f'syslog mode = {syslog_mode}',
                'Use reliable (TCP) syslog for critical log delivery: set mode reliable',
                'config log syslogd setting', actual=syslog_mode)

        # 3.1.3 Syslog severity level
        syslog_level = self._global('log syslogd setting', 'severity')
        if syslog_level:
            sev_map = {'emergency':0, 'alert':1, 'critical':2, 'error':3, 'warning':4,
                       'notification':5, 'information':6, 'debug':7}
            level_num = sev_map.get(syslog_level.lower(), 9)
            status = CheckResult.PASS if level_num >= 5 else CheckResult.WARN
            self._add('3.1.3', 'Syslog severity captures info-level events', 'HIGH', status,
                f'severity = {syslog_level}',
                'Set severity to "information" or lower to capture all relevant events.',
                'config log syslogd setting', actual=syslog_level)

        # 3.2.1 Email alerting
        smtp_server = self._global('system alertemail', 'server')
        alert_email = self._global('system alertemail', 'to')
        if smtp_server and alert_email:
            self._add('3.2.1', 'Email alerting configured', 'HIGH', CheckResult.PASS,
                f'SMTP server = {smtp_server}, alert-to = {alert_email}',
                '', 'config system alertemail', actual=smtp_server)
        else:
            self._add('3.2.1', 'Email alerting configured', 'HIGH', CheckResult.FAIL,
                f'Email alerting not fully configured. server={smtp_server}, to={alert_email}',
                'Configure: config system alertemail > set server <ip> > set to <email>',
                'config system alertemail')

    # ════════════════════════════════════════════════════════════════════════
    # SECTION 4 — WAF POLICY
    # ════════════════════════════════════════════════════════════════════════

    def _section4_waf_policy(self):
        print("[*] Section 4: WAF Policy Configuration")

        # 4.1.1 / 4.1.2 Server policies — WAF profile and action
        policies = self._entries('server-policy policy')
        for pname, pdata in policies.items():
            waf_profile = pdata.get('waf-profile', pdata.get('inline-protection-profile', ''))
            action      = pdata.get('action', '')
            http_to_https = pdata.get('http-to-https', 'disable')

            if waf_profile:
                self._add('4.1.1', f'WAF profile applied [{pname}]', 'CRITICAL', CheckResult.PASS,
                    f'Policy "{pname}" has WAF profile: {waf_profile}',
                    '', 'config server-policy policy', actual=waf_profile)
            else:
                self._add('4.1.1', f'WAF profile applied [{pname}]', 'CRITICAL', CheckResult.FAIL,
                    f'Policy "{pname}" has NO WAF profile applied — traffic is unprotected!',
                    f'Assign a WAF profile: set waf-profile <profile-name>',
                    'config server-policy policy')

            # 4.1.4 HTTP to HTTPS redirect
            if http_to_https == 'enable':
                self._add('4.1.4', f'HTTP→HTTPS redirect enabled [{pname}]', 'HIGH', CheckResult.PASS,
                    f'Policy "{pname}": http-to-https = enable',
                    '', 'config server-policy policy', actual=http_to_https)
            else:
                self._add('4.1.4', f'HTTP→HTTPS redirect enabled [{pname}]', 'HIGH', CheckResult.WARN,
                    f'Policy "{pname}": http-to-https = {http_to_https} — HTTP traffic not redirected.',
                    'Enable HTTPS redirect: set http-to-https enable',
                    'config server-policy policy', actual=http_to_https)

        # 4.2.x WAF Signature profiles
        sig_profiles = self._entries('waf signature')
        for pname, pdata in sig_profiles.items():
            sql = pdata.get('sql-injection-detection', 'disable')
            xss = pdata.get('xss-detection', 'disable')

            self._add('4.2.1', f'SQL Injection protection enabled [{pname}]', 'CRITICAL',
                CheckResult.PASS if sql == 'enable' else CheckResult.FAIL,
                f'sql-injection-detection = {sql}',
                'Enable SQL injection detection in WAF signature profile.',
                'config waf signature', actual=sql)

            self._add('4.2.2', f'XSS protection enabled [{pname}]', 'CRITICAL',
                CheckResult.PASS if xss == 'enable' else CheckResult.FAIL,
                f'xss-detection = {xss}',
                'Enable XSS detection in WAF signature profile.',
                'config waf signature', actual=xss)

        # 4.3.4 HTTP method policy
        method_policies = self._entries('waf http-method-policy')
        if method_policies:
            self._add('4.3.4', 'HTTP method policy defined', 'HIGH', CheckResult.PASS,
                f'{len(method_policies)} HTTP method policy/policies found.',
                '', 'config waf http-method-policy')
        else:
            self._add('4.3.4', 'HTTP method policy defined', 'HIGH', CheckResult.WARN,
                'No HTTP method policy found — all HTTP methods may be allowed.',
                'Define HTTP method policy restricting to required methods only.',
                'config waf http-method-policy')

    # ════════════════════════════════════════════════════════════════════════
    # SECTION 5 — SSL/TLS
    # ════════════════════════════════════════════════════════════════════════

    def _section5_ssl_tls(self):
        print("[*] Section 5: SSL/TLS Configuration")

        ssl_min = self._global('system global', 'ssl-min-proto-version')
        # Also check in server-policy ssl-profile
        ssl_min_sp = self._global('server-policy custom-application-policy', 'ssl-min-proto-version')
        effective_ssl = ssl_min or ssl_min_sp

        bad_versions = ['sslv3', 'tlsv1', 'tlsv1-0', 'tlsv1-1', 'tlsv1.0', 'tlsv1.1', 'ssl3', 'tls1', 'tls1.0', 'tls1.1']

        if effective_ssl:
            ev_lower = effective_ssl.lower()
            if any(bv in ev_lower for bv in bad_versions):
                self._add('5.2.3', 'TLS minimum version >= 1.2', 'CRITICAL', CheckResult.FAIL,
                    f'ssl-min-proto-version = {effective_ssl} — weak TLS version allowed!',
                    'Set: set ssl-min-proto-version TLSv1-2',
                    'config system global', actual=effective_ssl)
            elif 'tlsv1-2' in ev_lower or 'tlsv1.2' in ev_lower:
                self._add('5.2.3', 'TLS minimum version >= 1.2', 'CRITICAL', CheckResult.PASS,
                    f'ssl-min-proto-version = {effective_ssl}',
                    '', 'config system global', actual=effective_ssl)
            else:
                self._add('5.2.3', 'TLS minimum version >= 1.2', 'CRITICAL', CheckResult.WARN,
                    f'ssl-min-proto-version = {effective_ssl} — verify this is TLS 1.2 or higher.',
                    'Confirm and set to TLSv1-2 minimum.',
                    'config system global', actual=effective_ssl)
        else:
            self._add('5.2.3', 'TLS minimum version configured', 'CRITICAL', CheckResult.SKIP,
                'ssl-min-proto-version not found in config.',
                'Explicitly configure: set ssl-min-proto-version TLSv1-2',
                'config system global')

        # 5.2.6 Weak cipher check (raw search)
        weak_ciphers = ['RC4', 'DES', 'arcfour', 'NULL', 'EXPORT', 'MD5']
        raw_matches = []
        for wc in weak_ciphers:
            matches = self.cfg.raw_search(rf'set\s+ssl-cipher\S*\s+.*{wc}')
            if matches:
                raw_matches.extend(matches)

        if raw_matches:
            self._add('5.2.6', 'Weak SSL ciphers disabled', 'CRITICAL', CheckResult.FAIL,
                f'Weak cipher references found: {raw_matches[:3]}',
                'Remove weak ciphers from all SSL profiles.',
                'config system global / ssl-profile', actual=str(raw_matches[:2]))
        else:
            self._add('5.2.6', 'Weak SSL ciphers disabled', 'CRITICAL', CheckResult.PASS,
                'No explicit weak cipher (RC4/DES/NULL/EXPORT) references found in config.',
                '', 'config system global')

        # 5.1.1 Certificates — check for self-signed indicators
        certs = self._entries('system certificate local')
        for cname, cdata in certs.items():
            issuer = cdata.get('issuer', '')
            subject = cdata.get('subject', '')
            # Self-signed: issuer == subject
            if issuer and subject and issuer.lower() == subject.lower():
                self._add('5.1.1', f'CA-signed certificate deployed [{cname}]', 'HIGH', CheckResult.FAIL,
                    f'Certificate "{cname}" appears self-signed (issuer = subject).',
                    'Replace self-signed cert with CA-signed certificate.',
                    'config system certificate local', actual=f'issuer={issuer}')
            elif cname:
                self._add('5.1.1', f'Certificate present [{cname}]', 'HIGH', CheckResult.INFO,
                    f'Certificate "{cname}" found. Manually verify it is CA-signed and not expired.',
                    '', 'config system certificate local')

    # ════════════════════════════════════════════════════════════════════════
    # SECTION 6 — ACCESS CONTROL & RATE LIMITING
    # ════════════════════════════════════════════════════════════════════════

    def _section6_access_control(self):
        print("[*] Section 6: Access Control & DoS Protection")

        # 6.1.1 IP Reputation
        ip_rep = self._global('waf ip-reputation', 'status')
        if ip_rep == 'enable':
            self._add('6.1.1', 'IP reputation database enabled', 'HIGH', CheckResult.PASS,
                'IP reputation status = enable', '', 'config waf ip-reputation', actual=ip_rep)
        else:
            self._add('6.1.1', 'IP reputation database enabled', 'HIGH', CheckResult.FAIL,
                f'IP reputation status = {ip_rep}',
                'Enable IP reputation: config waf ip-reputation > set status enable',
                'config waf ip-reputation', actual=ip_rep)

        # 6.2.1 HTTP flood prevention
        flood_policies = self._entries('waf http-flood-prevention')
        if flood_policies:
            for fname, fdata in flood_policies.items():
                status_val = fdata.get('status', 'disable')
                threshold  = fdata.get('request-threshold', fdata.get('limit', ''))
                self._add('6.2.1', f'HTTP flood protection enabled [{fname}]', 'CRITICAL',
                    CheckResult.PASS if status_val == 'enable' else CheckResult.FAIL,
                    f'status = {status_val}, threshold = {threshold}',
                    'Enable HTTP flood prevention and set a rate threshold.',
                    'config waf http-flood-prevention', actual=f'{status_val}/{threshold}')
        else:
            self._add('6.2.1', 'HTTP flood protection configured', 'CRITICAL', CheckResult.FAIL,
                'No HTTP flood prevention policy found.',
                'Configure: config waf http-flood-prevention with appropriate thresholds.',
                'config waf http-flood-prevention')

        # 6.2.7 DoS protection linked to server policies
        policies = self._entries('server-policy policy')
        for pname, pdata in policies.items():
            dos_profile = pdata.get('dos-protection-profile', pdata.get('dos-prevention-policy', ''))
            if dos_profile:
                self._add('6.2.7', f'DoS protection profile applied [{pname}]', 'CRITICAL', CheckResult.PASS,
                    f'Policy "{pname}": dos-protection-profile = {dos_profile}',
                    '', 'config server-policy policy', actual=dos_profile)
            else:
                self._add('6.2.7', f'DoS protection profile applied [{pname}]', 'CRITICAL', CheckResult.FAIL,
                    f'Policy "{pname}" has no DoS protection profile applied.',
                    'Link a DoS prevention policy to all server policies.',
                    'config server-policy policy')

        # 6.1.2 Tor blocking
        tor = self._global('waf ip-reputation', 'tor-exit-node')
        if tor:
            self._add('6.1.2', 'Tor exit node blocking enabled', 'HIGH',
                CheckResult.PASS if tor == 'enable' else CheckResult.FAIL,
                f'tor-exit-node = {tor}',
                'Enable Tor blocking: set tor-exit-node enable',
                'config waf ip-reputation', actual=tor)

    # ════════════════════════════════════════════════════════════════════════
    # SECTION 7 — AUTHENTICATION & SESSIONS
    # ════════════════════════════════════════════════════════════════════════

    def _section7_authentication(self):
        print("[*] Section 7: Authentication & Session Management")

        # 7.1.3 LDAP uses LDAPS
        ldap_servers = self._entries('user ldap')
        for lname, ldata in ldap_servers.items():
            port   = ldata.get('port', '389')
            secure = ldata.get('secure', 'disable')
            if port == '636' or secure == 'enable':
                self._add('7.1.3', f'LDAP uses LDAPS [{lname}]', 'HIGH', CheckResult.PASS,
                    f'LDAP server "{lname}": port={port}, secure={secure}',
                    '', 'config user ldap', actual=f'port={port}')
            else:
                self._add('7.1.3', f'LDAP uses LDAPS [{lname}]', 'HIGH', CheckResult.FAIL,
                    f'LDAP server "{lname}": port={port}, secure={secure} — plain LDAP in use!',
                    'Configure LDAPS: set port 636 and set secure enable',
                    'config user ldap', actual=f'port={port}, secure={secure}')

        # 7.1.5 Cookie security
        cookie_profiles = self._entries('waf cookie-security')
        for cname, cdata in cookie_profiles.items():
            httponly  = cdata.get('httponly', 'disable')
            secure_c  = cdata.get('secure', 'disable')
            sign      = cdata.get('cookie-sign', cdata.get('sign', 'disable'))

            self._add('7.1.5', f'Cookie HttpOnly+Secure flags [{cname}]', 'HIGH',
                CheckResult.PASS if httponly == 'enable' and secure_c == 'enable' else CheckResult.FAIL,
                f'httponly={httponly}, secure={secure_c}',
                'Enable both flags: set httponly enable, set secure enable',
                'config waf cookie-security', actual=f'httponly={httponly},secure={secure_c}')

            self._add('7.1.6', f'Cookie signing enabled [{cname}]', 'HIGH',
                CheckResult.PASS if sign == 'enable' else CheckResult.FAIL,
                f'cookie-sign = {sign}',
                'Enable cookie signing to prevent tampering: set cookie-sign enable',
                'config waf cookie-security', actual=sign)

        if not cookie_profiles:
            self._add('7.1.5', 'Cookie security profile configured', 'HIGH', CheckResult.WARN,
                'No cookie security profiles found in config.',
                'Configure cookie security profiles with HttpOnly and Secure flags.',
                'config waf cookie-security')

    # ════════════════════════════════════════════════════════════════════════
    # SECTION 8 — SECURITY HEADERS
    # ════════════════════════════════════════════════════════════════════════

    def _section8_security_headers(self):
        print("[*] Section 8: Security Headers")

        header_profiles = self._entries('waf http-header-security')
        if not header_profiles:
            self._add('8.1.1', 'HTTP security headers configured', 'HIGH', CheckResult.FAIL,
                'No HTTP header security profiles found.',
                'Create and apply HTTP header security profiles to all server policies.',
                'config waf http-header-security')
            return

        checks = [
            ('8.1.1', 'X-Frame-Options header', 'x-frame-options', ['DENY', 'SAMEORIGIN'], 'HIGH'),
            ('8.1.2', 'X-Content-Type-Options header', 'x-content-type-options', ['nosniff'], 'MEDIUM'),
            ('8.1.3', 'X-XSS-Protection header', 'x-xss-protection', ['enable', '1'], 'MEDIUM'),
            ('8.1.5', 'HSTS header configured', 'hsts', ['enable'], 'HIGH'),
            ('8.1.6', 'Server header removed/masked', 'server-header', ['remove', 'custom'], 'MEDIUM'),
        ]

        for pname, pdata in header_profiles.items():
            for cid, ctitle, ckey, expected_vals, sev in checks:
                actual = pdata.get(ckey, '')
                matched = any(ev.lower() in actual.lower() for ev in expected_vals) if actual else False
                self._add(cid, f'{ctitle} [{pname}]', sev,
                    CheckResult.PASS if matched else (CheckResult.FAIL if not actual else CheckResult.WARN),
                    f'{ckey} = "{actual}"',
                    f'Set {ckey} to one of: {expected_vals}',
                    'config waf http-header-security', actual=actual)

    # ════════════════════════════════════════════════════════════════════════
    # SECTION 9 — ADVANCED THREATS
    # ════════════════════════════════════════════════════════════════════════

    def _section9_advanced_threats(self):
        print("[*] Section 9: Advanced Threat Protection")

        # 9.1.1 Bot detection
        bot_policies = self._entries('waf bot-detection-policy')
        if bot_policies:
            for bname, bdata in bot_policies.items():
                action = bdata.get('action', bdata.get('known-bot-action', ''))
                self._add('9.1.3', f'Bot action = block [{bname}]', 'HIGH',
                    CheckResult.PASS if 'block' in action.lower() else CheckResult.FAIL,
                    f'Malicious bot action = {action}',
                    'Set action to block for malicious bots.',
                    'config waf bot-detection-policy', actual=action)
        else:
            self._add('9.1.1', 'Bot detection policy configured', 'HIGH', CheckResult.FAIL,
                'No bot detection policies found.',
                'Configure bot detection: config waf bot-detection-policy',
                'config waf bot-detection-policy')

        # 9.2.1 DLP
        dlp_policies = self._entries('waf dlp-policy')
        if dlp_policies:
            self._add('9.2.1', 'DLP policy configured', 'HIGH', CheckResult.PASS,
                f'{len(dlp_policies)} DLP policy/policies found.',
                '', 'config waf dlp-policy')
        else:
            self._add('9.2.1', 'DLP policy configured', 'HIGH', CheckResult.WARN,
                'No DLP policies found.',
                'Configure DLP to protect sensitive data in responses.',
                'config waf dlp-policy')

    # ════════════════════════════════════════════════════════════════════════
    # SECTION 10 — HIGH AVAILABILITY
    # ════════════════════════════════════════════════════════════════════════

    def _section10_ha(self):
        print("[*] Section 10: High Availability")

        ha_mode = self._global('system ha', 'mode')
        if ha_mode in [None, 'standalone']:
            self._add('10.1.1', 'HA mode configured', 'HIGH', CheckResult.INFO,
                f'HA mode = {ha_mode} — standalone deployment.',
                'Consider HA if high availability is a requirement.',
                'config system ha', actual=ha_mode)
            return

        # HA is configured — check remaining controls
        ha_pass = self._global('system ha', 'group-password')
        ha_group_id = self._global('system ha', 'group-id')
        session_sync = self._global('system ha', 'session-sync')

        self._add('10.1.1', 'HA mode configured', 'HIGH', CheckResult.PASS,
            f'HA mode = {ha_mode}', '', 'config system ha', actual=ha_mode)

        if ha_pass:
            # Can't read plaintext password from config — just verify it's set
            self._add('10.1.3', 'HA group-password configured', 'CRITICAL', CheckResult.PASS,
                'HA group-password is set (value not shown for security).',
                '', 'config system ha')
        else:
            self._add('10.1.3', 'HA group-password configured', 'CRITICAL', CheckResult.FAIL,
                'HA group-password not found — HA cluster unprotected.',
                'Set: set group-password <strong-password>',
                'config system ha')

        if ha_group_id and ha_group_id != '0':
            self._add('10.1.4', 'HA group-id not default', 'MEDIUM', CheckResult.PASS,
                f'group-id = {ha_group_id}', '', 'config system ha', actual=ha_group_id)
        else:
            self._add('10.1.4', 'HA group-id not default', 'MEDIUM', CheckResult.WARN,
                f'group-id = {ha_group_id} — using default value.',
                'Change group-id to a non-default value.',
                'config system ha', actual=ha_group_id)

        self._add('10.1.5', 'HA session sync enabled', 'HIGH',
            CheckResult.PASS if session_sync == 'enable' else CheckResult.WARN,
            f'session-sync = {session_sync}',
            'Enable session sync for stateful failover.',
            'config system ha', actual=session_sync)

    # ════════════════════════════════════════════════════════════════════════
    # SECTION 11 — BACKUP
    # ════════════════════════════════════════════════════════════════════════

    def _section11_backup(self):
        print("[*] Section 11: Backup & Change Management")

        # Auto backup usually in system auto-backup or system global
        backup_server = self._global('system auto-backup', 'server')
        backup_status = self._global('system auto-backup', 'status')

        if backup_status == 'enable' and backup_server:
            self._add('11.1.1', 'Automatic backup configured', 'HIGH', CheckResult.PASS,
                f'Auto-backup enabled, server = {backup_server}',
                '', 'config system auto-backup', actual=backup_server)
        else:
            self._add('11.1.1', 'Automatic backup configured', 'HIGH', CheckResult.WARN,
                f'Automatic backup not configured or not enabled. status={backup_status}',
                'Configure scheduled backup to a remote SCP/FTP/SFTP server.',
                'config system auto-backup')


# ─────────────────────────────────────────────────────────────────────────────
# REPORT GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

class ReportGenerator:
    STATUS_COLORS = {
        CheckResult.PASS: '#10B981',
        CheckResult.FAIL: '#EF4444',
        CheckResult.WARN: '#F59E0B',
        CheckResult.INFO: '#60A5FA',
        CheckResult.SKIP: '#8B949E',
    }
    SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}

    def __init__(self, results, config_file):
        self.results = sorted(results, key=lambda r: (
            self.SEVERITY_ORDER.get(r.severity, 9),
            r.control_id
        ))
        self.config_file = config_file

    def _stats(self):
        total   = len(self.results)
        passed  = sum(1 for r in self.results if r.status == CheckResult.PASS)
        failed  = sum(1 for r in self.results if r.status == CheckResult.FAIL)
        warned  = sum(1 for r in self.results if r.status == CheckResult.WARN)
        skipped = sum(1 for r in self.results if r.status in [CheckResult.SKIP, CheckResult.INFO])
        critical_fails = sum(1 for r in self.results if r.status == CheckResult.FAIL and r.severity == 'CRITICAL')
        return total, passed, failed, warned, skipped, critical_fails

    def to_html(self, output_path):
        total, passed, failed, warned, skipped, crit_fails = self._stats()
        score = int((passed / total) * 100) if total else 0
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        rows = ""
        for r in self.results:
            color = self.STATUS_COLORS.get(r.status, '#8B949E')
            sev_color = {
                'CRITICAL': '#EF4444', 'HIGH': '#F97316',
                'MEDIUM': '#F59E0B', 'LOW': '#60A5FA'
            }.get(r.severity, '#8B949E')

            actual_cell = f'<code style="font-size:11px;color:#A0AEC0">{r.actual_value}</code>' if r.actual_value else '—'
            rec_cell = f'<span style="color:#A0AEC0">{r.recommendation}</span>' if r.recommendation else '—'

            rows += f"""
            <tr>
                <td style="color:#8B949E;font-family:Consolas">{r.control_id}</td>
                <td>{r.title}</td>
                <td><span style="background:{sev_color}22;color:{sev_color};padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold">{r.severity}</span></td>
                <td><span style="background:{color}22;color:{color};padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold">{r.status}</span></td>
                <td style="color:#E6EDF3">{r.finding}</td>
                <td>{actual_cell}</td>
                <td><code style="font-size:10px;color:#7C3AED">{r.config_path}</code></td>
                <td>{rec_cell}</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>FortiWeb 1000F — Configuration Audit Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #0D1117; color: #E6EDF3; font-family: Calibri, Arial, sans-serif; padding: 30px; }}
  h1 {{ font-size: 28px; color: #fff; letter-spacing: 2px; text-transform: uppercase; }}
  h2 {{ font-size: 14px; color: #00D4FF; margin: 20px 0 10px; text-transform: uppercase; letter-spacing: 1px; }}
  .meta {{ color: #8B949E; font-size: 13px; margin: 8px 0 25px; }}
  .stat-grid {{ display: flex; gap: 15px; margin: 20px 0; flex-wrap: wrap; }}
  .stat {{ background: #161B22; border: 1px solid #21262D; border-radius: 8px; padding: 15px 22px; min-width: 140px; }}
  .stat .val {{ font-size: 32px; font-weight: bold; font-family: Consolas; }}
  .stat .lbl {{ font-size: 11px; color: #8B949E; text-transform: uppercase; margin-top: 4px; }}
  .score {{ font-size: 48px; font-weight: bold; color: {'#10B981' if score >= 75 else '#F59E0B' if score >= 50 else '#EF4444'}; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 15px; }}
  th {{ background: #161B22; color: #8B949E; text-transform: uppercase; font-size: 10px; letter-spacing: 1px; padding: 10px 12px; text-align: left; border-bottom: 1px solid #21262D; position: sticky; top: 0; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #161B22; vertical-align: top; }}
  tr:hover td {{ background: #161B22; }}
  code {{ background: #0D1B2A; padding: 2px 6px; border-radius: 3px; font-family: Consolas; }}
  .filter-bar {{ margin: 15px 0; display: flex; gap: 10px; flex-wrap: wrap; }}
  .filter-btn {{ background: #161B22; border: 1px solid #21262D; color: #8B949E; padding: 6px 14px; border-radius: 6px; cursor: pointer; font-size: 12px; }}
  .filter-btn.active, .filter-btn:hover {{ border-color: #00D4FF; color: #00D4FF; }}
  .top-stripe {{ height: 4px; background: linear-gradient(90deg, #00D4FF, #7C3AED); margin-bottom: 25px; border-radius: 2px; }}
</style>
</head>
<body>
<div class="top-stripe"></div>
<h1>🛡️ FortiWeb 1000F — Configuration Audit Report</h1>
<div class="meta">
  File: <code>{self.config_file}</code> &nbsp;|&nbsp; 
  Generated: {timestamp} &nbsp;|&nbsp; 
  Benchmark: FortiWeb Hardening Guide v1.0
</div>

<h2>Executive Summary</h2>
<div class="stat-grid">
  <div class="stat"><div class="val score">{score}%</div><div class="lbl">Compliance Score</div></div>
  <div class="stat"><div class="val" style="color:#E6EDF3">{total}</div><div class="lbl">Total Controls</div></div>
  <div class="stat"><div class="val" style="color:#10B981">{passed}</div><div class="lbl">Passed</div></div>
  <div class="stat"><div class="val" style="color:#EF4444">{failed}</div><div class="lbl">Failed</div></div>
  <div class="stat"><div class="val" style="color:#F59E0B">{warned}</div><div class="lbl">Warnings</div></div>
  <div class="stat"><div class="val" style="color:#8B949E">{skipped}</div><div class="lbl">Skipped/Info</div></div>
  <div class="stat"><div class="val" style="color:#EF4444">{crit_fails}</div><div class="lbl">Critical Failures</div></div>
</div>

<h2>Audit Findings</h2>
<div class="filter-bar">
  <button class="filter-btn active" onclick="filterTable('ALL')">All</button>
  <button class="filter-btn" onclick="filterTable('FAIL')" style="color:#EF4444;border-color:#EF4444">Failed</button>
  <button class="filter-btn" onclick="filterTable('WARN')" style="color:#F59E0B;border-color:#F59E0B">Warnings</button>
  <button class="filter-btn" onclick="filterTable('CRITICAL')" style="color:#EF4444">Critical Only</button>
  <button class="filter-btn" onclick="filterTable('PASS')" style="color:#10B981">Passed</button>
</div>

<table id="results-table">
<thead>
  <tr>
    <th>ID</th><th>Control</th><th>Severity</th><th>Status</th>
    <th>Finding</th><th>Actual Value</th><th>Config Path</th><th>Recommendation</th>
  </tr>
</thead>
<tbody>
{rows}
</tbody>
</table>

<div style="margin-top:30px;color:#8B949E;font-size:11px">
  <p>⚠️ This report is confidential. Some controls marked SKIP require manual verification on the device.</p>
  <p>Script: fortiweb_audit.py | Benchmark: FortiWeb 1000F Hardening Benchmark v1.0</p>
</div>

<script>
function filterTable(filter) {{
  const rows = document.querySelectorAll('#results-table tbody tr');
  rows.forEach(row => {{
    const sev = row.cells[2].textContent.trim();
    const status = row.cells[3].textContent.trim();
    if (filter === 'ALL') {{ row.style.display = ''; }}
    else if (filter === 'CRITICAL') {{ row.style.display = sev === 'CRITICAL' ? '' : 'none'; }}
    else {{ row.style.display = status === filter ? '' : 'none'; }}
  }});
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
}}
</script>
</body>
</html>"""

        with open(output_path, 'w') as f:
            f.write(html)
        print(f"[+] HTML report saved: {output_path}")

    def to_csv(self, output_path):
        import csv
        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Control ID', 'Title', 'Severity', 'Status', 'Finding', 'Actual Value', 'Config Path', 'Recommendation'])
            for r in self.results:
                writer.writerow([r.control_id, r.title, r.severity, r.status, r.finding,
                                  r.actual_value or '', r.config_path, r.recommendation])
        print(f"[+] CSV report saved: {output_path}")

    def to_text(self):
        total, passed, failed, warned, skipped, crit_fails = self._stats()
        print("\n" + "="*80)
        print("  FORTIWEB 1000F — CONFIGURATION AUDIT REPORT")
        print("="*80)
        print(f"  File     : {self.config_file}")
        print(f"  Date     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Score    : {int((passed/total)*100) if total else 0}%  |  "
              f"PASS:{passed}  FAIL:{failed}  WARN:{warned}  SKIP:{skipped}  CRIT_FAIL:{crit_fails}")
        print("="*80 + "\n")

        for r in self.results:
            icon = {'PASS':'✓','FAIL':'✗','WARN':'⚠','INFO':'ℹ','SKIP':'?'}.get(r.status, '?')
            print(f"[{icon}] [{r.severity:<8}] {r.control_id:<8} {r.title}")
            print(f"     Status  : {r.status}")
            print(f"     Finding : {r.finding}")
            if r.actual_value:
                print(f"     Actual  : {r.actual_value}")
            if r.recommendation:
                print(f"     Fix     : {r.recommendation}")
            print(f"     Path    : {r.config_path}")
            print()


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='FortiWeb 1000F Configuration Audit Script',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 fortiweb_audit.py fortiweb.conf
  python3 fortiweb_audit.py fortiweb.conf --output report.html --format html
  python3 fortiweb_audit.py fortiweb.conf --output findings.csv --format csv
  python3 fortiweb_audit.py fortiweb.conf --format text
  python3 fortiweb_audit.py fortiweb.conf --severity CRITICAL HIGH
        """
    )
    parser.add_argument('config_file', help='Path to FortiWeb .conf file')
    parser.add_argument('--output', '-o', help='Output file path (default: fortiweb_audit_report.html)')
    parser.add_argument('--format', '-f', choices=['html', 'csv', 'text'], default='html', help='Output format')
    parser.add_argument('--severity', nargs='+', choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                        help='Filter results by severity')
    parser.add_argument('--status', nargs='+', choices=['PASS', 'FAIL', 'WARN', 'INFO', 'SKIP'],
                        help='Filter results by status')
    parser.add_argument('--failed-only', action='store_true', help='Show only failed/warning controls')

    args = parser.parse_args()

    # Load & parse config
    cfg_parser = FortiWebConfigParser(args.config_file)
    cfg_parser.load()
    print(f"[+] Loaded config: {args.config_file}")
    print(f"[+] Config sections found: {len(cfg_parser.config_tree)}")

    # Run audit
    auditor = FortiWebAuditor(cfg_parser)
    results = auditor.run_all()

    # Apply filters
    if args.severity:
        results = [r for r in results if r.severity in args.severity]
    if args.status:
        results = [r for r in results if r.status in args.status]
    if args.failed_only:
        results = [r for r in results if r.status in [CheckResult.FAIL, CheckResult.WARN]]

    # Generate report
    output_path = args.output or f"fortiweb_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    reporter = ReportGenerator(results, args.config_file)

    if args.format == 'html':
        reporter.to_html(output_path)
    elif args.format == 'csv':
        if not output_path.endswith('.csv'):
            output_path = output_path.replace('.html', '.csv')
        reporter.to_csv(output_path)
    elif args.format == 'text':
        reporter.to_text()

    # Always print summary to console
    total, passed, failed, warned, skipped, crit_fails = reporter._stats()
    print(f"\n{'='*50}")
    print(f"  SUMMARY: {passed} PASS | {failed} FAIL | {warned} WARN | {skipped} SKIP")
    print(f"  CRITICAL FAILURES: {crit_fails}")
    print(f"  COMPLIANCE SCORE : {int((passed/total)*100) if total else 0}%")
    print(f"{'='*50}\n")

    if crit_fails > 0:
        print(f"[!] {crit_fails} CRITICAL failures found — remediate immediately.")
        sys.exit(2)
    elif failed > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
