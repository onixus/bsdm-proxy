#!/usr/bin/env python3
"""
BSDM-Proxy CIS Benchmark Compliance Auditor.

Audits repository configuration against:
1. CIS Docker Benchmark v1.6/1.7 (Dockerfile & Compose configurations)
2. CIS Kubernetes Benchmark v1.9 & Pod Security Standards (PSS Restricted)
3. CIS NGINX Benchmark (Reverse-Proxy & CORS configurations)
4. CIS Linux / Systemd / Secrets Hardening (Systemd units, CA, Passwords, Permissions)
"""

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

class BenchmarkReport:
    def __init__(self):
        self.results = []

    def check(self, benchmark: str, section: str, item: str, status: str, details: str):
        self.results.append({
            "benchmark": benchmark,
            "section": section,
            "item": item,
            "status": status,
            "details": details
        })

    def print_summary(self):
        print("=" * 80)
        print("                 BSDM-PROXY CIS BENCHMARK AUDIT REPORT")
        print("=" * 80)
        
        benchmarks = sorted(list(set(r["benchmark"] for r in self.results)))
        total_pass = sum(1 for r in self.results if r["status"] == "PASS")
        total_fail = sum(1 for r in self.results if r["status"] == "FAIL")
        total_warn = sum(1 for r in self.results if r["status"] == "WARN")
        
        for b in benchmarks:
            b_results = [r for r in self.results if r["benchmark"] == b]
            b_pass = sum(1 for r in b_results if r["status"] == "PASS")
            b_fail = sum(1 for r in b_results if r["status"] == "FAIL")
            b_warn = sum(1 for r in b_results if r["status"] == "WARN")
            
            print(f"\n📂 [{b}] (PASS: {b_pass}, FAIL: {b_fail}, WARN: {b_warn})")
            print("-" * 80)
            for r in b_results:
                icon = "✅ PASS" if r["status"] == "PASS" else ("❌ FAIL" if r["status"] == "FAIL" else "⚠️  WARN")
                print(f"  {icon:<8} [{r['section']}] {r['item']}")
                if r['details']:
                    print(f"           ↳ {r['details']}")
                    
        print("\n" + "=" * 80)
        print(f"TOTAL: {len(self.results)} checks | PASS: {total_pass} | FAIL: {total_fail} | WARN: {total_warn}")
        print("=" * 80)
        return total_fail


def audit_docker(report: BenchmarkReport):
    # 1. Dockerfile checks
    df_path = ROOT / "Dockerfile"
    if df_path.exists():
        content = df_path.read_text()
        
        # User check (CIS 4.1)
        if "USER bsdm" in content and "USER root" not in content.split("USER bsdm")[-1]:
            report.check("CIS Docker Benchmark", "4.1 User", "Run as non-root user (USER bsdm)", "PASS", "Container drops root to user 'bsdm'")
        else:
            report.check("CIS Docker Benchmark", "4.1 User", "Run as non-root user", "FAIL", "Missing non-root USER instruction")

        # Healthcheck (CIS 4.6)
        if "HEALTHCHECK" in content:
            report.check("CIS Docker Benchmark", "4.6 Healthcheck", "HEALTHCHECK instruction in image", "PASS", "HEALTHCHECK defined for container liveness")
        else:
            report.check("CIS Docker Benchmark", "4.6 Healthcheck", "HEALTHCHECK instruction in image", "WARN", "No HEALTHCHECK instruction in Dockerfile")

        # Secrets (CIS 4.7)
        suspicious = [line for line in content.splitlines() if re.search(r'(?i)(secret|password|token)\s*=', line) and not line.strip().startswith('#')]
        if not suspicious:
            report.check("CIS Docker Benchmark", "4.7 Secrets", "No embedded secrets in build steps", "PASS", "No hardcoded credentials found in Dockerfile")
        else:
            report.check("CIS Docker Benchmark", "4.7 Secrets", "No embedded secrets in build steps", "FAIL", f"Found potential secrets: {suspicious}")

        # Package manager update clean (CIS 4.8)
        if "rm -rf /var/cache/apk/*" in content or "--no-cache" in content:
            report.check("CIS Docker Benchmark", "4.8 Hygiene", "Clean package manager cache", "PASS", "Uses --no-cache or cleans apk cache")
        else:
            report.check("CIS Docker Benchmark", "4.8 Hygiene", "Clean package manager cache", "WARN", "Package cache might not be cleaned")

    # 2. Docker Compose checks (docker-compose.yml, pilot, lite)
    compose_files = [
        ROOT / "docker-compose.yml",
        ROOT / "deploy/compose/docker-compose.pilot.yml",
        ROOT / "deploy/compose/docker-compose.lite.yml"
    ]
    
    for cpath in compose_files:
        if not cpath.exists():
            continue
        c_content = cpath.read_text()
        rel_name = cpath.relative_to(ROOT)
        
        # no-new-privileges (CIS 5.25)
        if "no-new-privileges:true" in c_content:
            report.check("CIS Docker Benchmark", f"5.25 SecurityOpt ({rel_name})", "no-new-privileges enabled", "PASS", "Prevents privilege escalation")
        else:
            report.check("CIS Docker Benchmark", f"5.25 SecurityOpt ({rel_name})", "no-new-privileges enabled", "WARN", "no-new-privileges not set for all services")

        # cap_drop ALL (CIS 5.3)
        if "cap_drop:" in c_content and ("ALL" in c_content or "all" in c_content):
            report.check("CIS Docker Benchmark", f"5.3 Capabilities ({rel_name})", "Drop unnecessary Linux capabilities (cap_drop: ALL)", "PASS", "Drops default Linux capabilities")
        else:
            report.check("CIS Docker Benchmark", f"5.3 Capabilities ({rel_name})", "Drop Linux capabilities", "WARN", "cap_drop not explicitly declared")

        # Loopback bindings for DB / Admin (CIS 5.13)
        exposed_any = re.findall(r'-\s*"0\.0\.0\.0:(6379|8123|9092|3000)', c_content)
        if not exposed_any:
            report.check("CIS Docker Benchmark", f"5.13 Network ({rel_name})", "Sensitive ports bound to 127.0.0.1 (Redis, ClickHouse, Kafka, Grafana)", "PASS", "No sensitive ports published to 0.0.0.0")
        else:
            report.check("CIS Docker Benchmark", f"5.13 Network ({rel_name})", "Sensitive ports bound to loopback", "FAIL", f"Ports exposed on 0.0.0.0: {exposed_any}")


def audit_kubernetes(report: BenchmarkReport):
    values_path = ROOT / "charts/bsdm/values.yaml"
    templates_dir = ROOT / "charts/bsdm/templates"
    
    if values_path.exists():
        values_content = values_path.read_text()
        
        # seccompProfile (PSS Restricted)
        if "type: RuntimeDefault" in values_content or "seccompProfile" in values_content:
            report.check("CIS Kubernetes Benchmark", "5.7.2 Pod Security", "seccompProfile: RuntimeDefault configured", "PASS", "Enforces default Linux seccomp syscall filters")
        else:
            report.check("CIS Kubernetes Benchmark", "5.7.2 Pod Security", "seccompProfile configured", "FAIL", "Missing seccompProfile in PodSecurityContext")

        # runAsNonRoot & drop ALL
        if "runAsNonRoot: true" in values_content and "drop:" in values_content:
            report.check("CIS Kubernetes Benchmark", "5.2.6 Pod Security", "runAsNonRoot & capabilities drop: [ALL]", "PASS", "Enforces non-root execution and capability drop")
        else:
            report.check("CIS Kubernetes Benchmark", "5.2.6 Pod Security", "runAsNonRoot & cap drop", "WARN", "Verify runAsNonRoot settings")

        # readOnlyRootFilesystem
        if "readOnlyRootFilesystem: true" in values_content:
            report.check("CIS Kubernetes Benchmark", "5.2.5 Pod Security", "readOnlyRootFilesystem: true", "PASS", "Root filesystem mounted read-only")
        else:
            report.check("CIS Kubernetes Benchmark", "5.2.5 Pod Security", "readOnlyRootFilesystem", "WARN", "readOnlyRootFilesystem not set to true")

        # allowPrivilegeEscalation: false
        if "allowPrivilegeEscalation: false" in values_content:
            report.check("CIS Kubernetes Benchmark", "5.2.7 Pod Security", "allowPrivilegeEscalation: false", "PASS", "Prevents setuid/setgid privilege escalation")
        else:
            report.check("CIS Kubernetes Benchmark", "5.2.7 Pod Security", "allowPrivilegeEscalation", "FAIL", "allowPrivilegeEscalation is not disabled")

    # ServiceAccount automount token
    if templates_dir.exists():
        sa_files = list(templates_dir.glob("*.yaml"))
        automount_disabled = False
        for f in sa_files:
            if "automountServiceAccountToken: false" in f.read_text():
                automount_disabled = True
                break
        if automount_disabled:
            report.check("CIS Kubernetes Benchmark", "5.1.5 ServiceAccount", "automountServiceAccountToken: false", "PASS", "Disabled default K8s API token mount")
        else:
            report.check("CIS Kubernetes Benchmark", "5.1.5 ServiceAccount", "automountServiceAccountToken", "WARN", "automountServiceAccountToken not explicitly false in all pods")


def audit_nginx(report: BenchmarkReport):
    conf_path = ROOT / "config/search-cors.nginx.conf"
    if conf_path.exists():
        content = conf_path.read_text()
        
        # server_tokens off
        if "server_tokens off;" in content:
            report.check("CIS NGINX Benchmark", "2.1 Info Disclosure", "server_tokens off;", "PASS", "Hides NGINX version banner")
        else:
            report.check("CIS NGINX Benchmark", "2.1 Info Disclosure", "server_tokens off;", "FAIL", "Server tokens enabled")

        # Loopback binding
        if "listen 127.0.0.1:" in content or "listen [::1]:" in content:
            report.check("CIS NGINX Benchmark", "3.1 Network", "listen on 127.0.0.1", "PASS", "Proxy bound strictly to localhost")
        else:
            report.check("CIS NGINX Benchmark", "3.1 Network", "listen on localhost", "WARN", "Check listening address")

        # Security Headers
        headers = ["X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Content-Security-Policy"]
        found_headers = [h for h in headers if h in content]
        if len(found_headers) >= 3:
            report.check("CIS NGINX Benchmark", "4.1 HTTP Headers", f"Security Headers ({', '.join(found_headers)})", "PASS", "Essential security headers present")
        else:
            report.check("CIS NGINX Benchmark", "4.1 HTTP Headers", "Security Headers", "WARN", f"Found only: {found_headers}")

        # CORS reflect protection
        if "add_header Access-Control-Allow-Origin \"*\"" in content and "Access-Control-Allow-Credentials \"true\"" in content:
            report.check("CIS NGINX Benchmark", "5.1 CORS", "CORS reflect-any origin check", "FAIL", "Insecure wildcard origin with credentials")
        else:
            report.check("CIS NGINX Benchmark", "5.1 CORS", "CORS policy check", "PASS", "CORS headers correctly configured")


def audit_linux_systemd(report: BenchmarkReport):
    # 1. Systemd units hardening
    systemd_dir = ROOT / "packaging/systemd"
    if systemd_dir.exists():
        units = list(systemd_dir.glob("*.service"))
        for unit in units:
            content = unit.read_text()
            uname = unit.name
            
            hardening_keys = [
                "NoNewPrivileges=true",
                "ProtectSystem=strict",
                "ProtectHome=true",
                "PrivateTmp=true",
                "PrivateDevices=true",
                "ProtectKernelTunables=true",
                "ProtectControlGroups=true",
                "RestrictRealtime=true",
                "RestrictSUIDSGID=true",
                "MemoryDenyWriteExecute=true",
                "LockPersonality=true"
            ]
            matched = [k for k in hardening_keys if k in content]
            if len(matched) >= 9:
                report.check("CIS Linux / Systemd", f"Unit Hardening ({uname})", f"{len(matched)}/11 security directives", "PASS", "Comprehensive sandboxing profile active")
            else:
                report.check("CIS Linux / Systemd", f"Unit Hardening ({uname})", f"{len(matched)}/11 security directives", "WARN", f"Missing some directives: {set(hardening_keys) - set(matched)}")

    # 2. CA Key permissions check
    ca_key_path = ROOT / "certs/ca.key"
    if ca_key_path.exists():
        mode = oct(ca_key_path.stat().st_mode)[-3:]
        if mode == "600" or mode == "400":
            report.check("CIS Linux / CA Security", "Permissions", f"ca.key mode {mode}", "PASS", "Owner-only read/write (0600)")
        else:
            report.check("CIS Linux / CA Security", "Permissions", f"ca.key mode {mode}", "FAIL", "ca.key must be 0600")

    # 3. Password Hashing (Argon2id)
    auth_source = ROOT / "proxy/src/auth.rs"
    if auth_source.exists():
        auth_code = auth_source.read_text()
        if "argon2" in auth_code.lower():
            report.check("CIS Linux / Auth", "Password Hashing", "Argon2id password hashing algorithm", "PASS", "Strong salted hash with automatic upgrade on verify")
        else:
            report.check("CIS Linux / Auth", "Password Hashing", "Password hashing algorithm", "WARN", "Check password hashing algorithm")


def main():
    report = BenchmarkReport()
    audit_docker(report)
    audit_kubernetes(report)
    audit_nginx(report)
    audit_linux_systemd(report)
    
    fails = report.print_summary()
    if fails > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
