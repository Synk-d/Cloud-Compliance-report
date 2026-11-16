import datetime

class CloudComplianceCollector:
    def __init__(self):
        # Default mock state jo CIS/NIST standards verify karega
        self.findings = [
            {
                "id": "s3-01",
                "service": "AWS S3",
                "resource": "arn:aws:s3:::bennett-student-backups",
                "rule": "CIS 2.1.4 - Public Access Block must be enabled",
                "status": "FAILED",
                "severity": "CRITICAL",
                "risk": "Publicly readable bucket exposing database backups."
            },
            {
                "id": "iam-01",
                "service": "AWS IAM",
                "resource": "arn:aws:iam::579112ba:user/admin-operator",
                "rule": "CIS 1.2 - Multi-Factor Authentication (MFA) Active",
                "status": "PASSED",
                "severity": "CRITICAL",
                "risk": "Admin login without hardware/software MFA token."
            },
            {
                "id": "ec2-01",
                "service": "AWS EC2 / SG",
                "resource": "sg-044391ab (default-security-group)",
                "rule": "CIS 4.1 - Ingress SSH on Port 22 Restricted",
                "status": "FAILED",
                "severity": "HIGH",
                "risk": "0.0.0.0/0 open SSH port allows brute-force attacks."
            },
            {
                "id": "az-nsg-01",
                "service": "Azure NSG",
                "resource": "/subscriptions/579112ba/nsg-prod",
                "rule": "CIS Azure 3.2 - No Open RDP Ports (3389)",
                "status": "PASSED",
                "severity": "CRITICAL",
                "risk": "Remote Desktop Protocol exposed to internet."
            }
        ]

    def run_scan(self):
        total = len(self.findings)
        passed = sum(1 for f in self.findings if f["status"] == "PASSED")
        score = round((passed / total) * 100) if total > 0 else 100

        return {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "compliance_score": score,
            "total_resources": total,
            "critical_violations": sum(1 for f in self.findings if f["status"] == "FAILED" and f["severity"] == "CRITICAL"),
            "high_violations": sum(1 for f in self.findings if f["status"] == "FAILED" and f["severity"] == "HIGH"),
            "findings": self.findings
        }

    def remediate_resource(self, resource_id):
        for f in self.findings:
            if f["id"] == resource_id or f["service"] in resource_id:
                f["status"] = "PASSED"
                f["risk"] = "Remediated via Automated AI Playbook. Security baseline enforced."
        return self.run_scan()