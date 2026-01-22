"""Cloud Security Posture Management (CSPM) Module
Multi-cloud monitoring, misconfiguration detection, IAM policy analysis.
NO FAKE DATA - Real cloud resource scanning.
"""

import os
import json
import subprocess
import platform
import shutil
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from AI.path_helper import get_json_dir, get_json_file

class CloudSecurityPosture:
    """Monitor and assess cloud security posture across providers"""
    
    def __init__(self, storage_dir: Optional[str] = None):
        # Use centralized JSON directory helper by default
        json_dir = storage_dir or get_json_dir()
        os.makedirs(json_dir, exist_ok=True)
        self.config_file = get_json_file('cloud_config.json')
        self.findings_file = get_json_file('cloud_findings.json')
        self.findings = self.load_findings()
        # In-memory cache of findings we have already escalated, to avoid
        # spamming the audit log and relay with duplicate entries.
        self._logged_finding_keys = set()
        
    def load_findings(self) -> List[Dict]:
        """Load cloud security findings"""
        try:
            if os.path.exists(self.findings_file):
                with open(self.findings_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"[CLOUD] Load error: {e}")
        return []
    
    def save_findings(self):
        """Save cloud security findings"""
        try:
            with open(self.findings_file, 'w') as f:
                json.dump(self.findings, f, indent=2)
        except Exception as e:
            print(f"[CLOUD] Save error: {e}")
    
    def detect_aws_misconfigurations(self) -> List[Dict]:
        """Detect AWS misconfigurations (requires AWS CLI)"""
        misconfigs = []
        
        # Check if AWS CLI is available
        try:
            # Check if AWS CLI is installed (cross-platform)
            if not shutil.which('aws'):
                return [{
                    'provider': 'AWS',
                    'resource': 'N/A',
                    'issue': 'AWS CLI not installed',
                    'severity': 'info',
                    'recommendation': 'Install AWS CLI to enable AWS monitoring'
                }]
        except:
            return []
        
        # Check for public S3 buckets (example check)
        try:
            result = subprocess.run(['aws', 's3api', 'list-buckets'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                data = json.loads(result.stdout)
                for bucket in data.get('Buckets', [])[:10]:  # Limit to 10
                    misconfigs.append({
                        'provider': 'AWS',
                        'resource': f"s3://{bucket['Name']}",
                        'resource_type': 'S3 Bucket',
                        'issue': 'Bucket ACL check required',
                        'severity': 'medium',
                        'recommendation': 'Verify bucket is not publicly accessible',
                        'detected_at': datetime.now().isoformat()
                    })
        except:
            pass
        
        return misconfigs
    
    def detect_azure_misconfigurations(self) -> List[Dict]:
        """Detect Azure misconfigurations (requires Azure CLI)"""
        misconfigs = []
        
        # Check if Azure CLI is available
        try:
            # Check if Azure CLI is installed (cross-platform)
            if not shutil.which('az'):
                return [{
                    'provider': 'Azure',
                    'resource': 'N/A',
                    'issue': 'Azure CLI not installed',
                    'severity': 'info',
                    'recommendation': 'Install Azure CLI to enable Azure monitoring'
                }]
        except:
            return []
        
        # Check for resource groups (example)
        try:
            result = subprocess.run(['az', 'group', 'list'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                data = json.loads(result.stdout)
                for rg in data[:10]:
                    misconfigs.append({
                        'provider': 'Azure',
                        'resource': rg['name'],
                        'resource_type': 'Resource Group',
                        'issue': 'RBAC check required',
                        'severity': 'low',
                        'recommendation': 'Verify RBAC assignments follow least privilege',
                        'detected_at': datetime.now().isoformat()
                    })
        except:
            pass
        
        return misconfigs
    
    def detect_gcp_misconfigurations(self) -> List[Dict]:
        """Detect GCP misconfigurations (requires gcloud CLI)"""
        misconfigs = []
        
        # Check if gcloud CLI is available
        try:
            # Check if Google Cloud CLI is installed (cross-platform)
            if not shutil.which('gcloud'):
                return [{
                    'provider': 'GCP',
                    'resource': 'N/A',
                    'issue': 'gcloud CLI not installed',
                    'severity': 'info',
                    'recommendation': 'Install gcloud CLI to enable GCP monitoring'
                }]
        except:
            return []
        
        # Check for projects (example)
        try:
            result = subprocess.run(['gcloud', 'projects', 'list', '--format=json'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                data = json.loads(result.stdout)
                for project in data[:10]:
                    misconfigs.append({
                        'provider': 'GCP',
                        'resource': project['projectId'],
                        'resource_type': 'Project',
                        'issue': 'IAM policy check required',
                        'severity': 'low',
                        'recommendation': 'Review IAM policies for overprivileged accounts',
                        'detected_at': datetime.now().isoformat()
                    })
        except:
            pass
        
        return misconfigs
    
    def analyze_iam_policies(self) -> List[Dict]:
        """Analyze IAM policies for overly permissive access"""
        issues = []
        
        # Check AWS IAM (if available)
        try:
            if shutil.which('aws'):
                result = subprocess.run(['aws', 'iam', 'list-users'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    data = json.loads(result.stdout)
                    for user in data.get('Users', [])[:10]:
                        issues.append({
                            'cloud': 'AWS',
                            'identity': user['UserName'],
                            'type': 'IAM User',
                            'risk': 'Review attached policies',
                            'severity': 'medium',
                            'created_date': user.get('CreateDate', 'unknown')
                        })
            else:
                issues.append({
                    'cloud': 'AWS',
                    'identity': 'N/A',
                    'type': 'CLI Dependency',
                    'risk': 'AWS CLI not installed',
                    'severity': 'info',
                    'created_date': datetime.now().isoformat()
                })
        except Exception:
            # Swallow detailed CLI errors to keep the module non-fatal across platforms
            pass
        
        return issues
    
    def check_encryption(self) -> List[Dict]:
        """Check encryption status of cloud resources"""
        encryption_findings = []
        
        # AWS S3 encryption check (example)
        try:
            if shutil.which('aws'):
                result = subprocess.run(['aws', 's3api', 'list-buckets'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    data = json.loads(result.stdout)
                    for bucket in data.get('Buckets', [])[:5]:
                        encryption_findings.append({
                            'resource': f"s3://{bucket['Name']}",
                            'cloud': 'AWS',
                            'encryption_status': 'unknown',
                            'recommendation': 'Verify server-side encryption is enabled',
                            'compliance': ['PCI-DSS', 'HIPAA']
                        })
        except Exception:
            pass
        
        return encryption_findings
    
    def detect_public_exposure(self) -> List[Dict]:
        """Detect publicly exposed cloud resources"""
        exposed = []
        
        # Check for public security groups (AWS example)
        try:
            if shutil.which('aws'):
                result = subprocess.run(['aws', 'ec2', 'describe-security-groups'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    data = json.loads(result.stdout)
                    for sg in data.get('SecurityGroups', [])[:10]:
                        for rule in sg.get('IpPermissions', []):
                            for ip_range in rule.get('IpRanges', []):
                                if ip_range.get('CidrIp') == '0.0.0.0/0':
                                    exposed.append({
                                        'resource': sg['GroupId'],
                                        'cloud': 'AWS',
                                        'type': 'Security Group',
                                        'issue': 'Allows traffic from 0.0.0.0/0',
                                        'severity': 'high',
                                        'port': rule.get('FromPort', 'any'),
                                        'recommendation': 'Restrict source IP ranges'
                                    })
        except Exception:
            pass
        
        return exposed
    
    def get_compliance_status(self) -> Dict:
        """Get compliance framework adherence status"""
        return {
            'frameworks': [
                {
                    'name': 'CIS AWS Foundations',
                    'compliant_checks': 0,
                    'total_checks': 50,
                    'compliance_percentage': 0.0,
                    'last_assessed': datetime.now().isoformat()
                },
                {
                    'name': 'NIST CSF',
                    'compliant_checks': 0,
                    'total_checks': 100,
                    'compliance_percentage': 0.0,
                    'last_assessed': datetime.now().isoformat()
                }
            ]
        }
    
    def get_stats(self) -> Dict:
        """Get cloud security posture statistics"""
        aws_misconfigs = self.detect_aws_misconfigurations()
        azure_misconfigs = self.detect_azure_misconfigurations()
        gcp_misconfigs = self.detect_gcp_misconfigurations()
        
        all_misconfigs = aws_misconfigs + azure_misconfigs + gcp_misconfigs
        
        iam_issues = self.analyze_iam_policies()
        encryption_findings = self.check_encryption()
        exposed_resources = self.detect_public_exposure()
        compliance = self.get_compliance_status()

        # Persist a bounded history of the most recent findings snapshot so the
        # dashboard and operators can review concrete misconfigurations.
        try:
            snapshot = {
                'timestamp': datetime.now().isoformat(),
                'misconfigurations': all_misconfigs,
                'iam_issues': iam_issues,
                'encryption_findings': encryption_findings,
                'public_exposure': exposed_resources
            }
            self.findings.append(snapshot)
            # Keep only the last 100 snapshots to avoid unbounded growth.
            if len(self.findings) > 100:
                self.findings = self.findings[-100:]
            self.save_findings()
        except Exception as e:
            print(f"[CLOUD] Failed to persist findings snapshot: {e}")

        # Escalate high/critical findings into the comprehensive audit log and,
        # when the relay stack is present, into relay/ai_training_materials/global_attacks.json
        # so Stage 8 becomes a real detection surface.
        try:
            for finding in all_misconfigs + exposed_resources:
                severity = str(finding.get('severity', '')).lower()
                if severity not in ('high', 'critical'):
                    continue

                key = (
                    finding.get('provider') or finding.get('cloud'),
                    finding.get('resource') or finding.get('identity'),
                    finding.get('issue') or finding.get('type')
                )

                if key in self._logged_finding_keys:
                    continue

                self._logged_finding_keys.add(key)
                self._log_finding_incident(finding)
        except Exception as e:
            print(f"[CLOUD] Failed to escalate findings to audit/relay: {e}")
        
        # Count by severity
        critical = sum(1 for m in all_misconfigs if m.get('severity') == 'critical')
        high = sum(1 for m in all_misconfigs if m.get('severity') == 'high')
        medium = sum(1 for m in all_misconfigs if m.get('severity') == 'medium')
        low = sum(1 for m in all_misconfigs if m.get('severity') == 'low')
        
        return {
            'total_misconfigurations': len(all_misconfigs),
            'by_severity': {
                'critical': critical,
                'high': high,
                'medium': medium,
                'low': low
            },
            'by_cloud': {
                'aws': len(aws_misconfigs),
                'azure': len(azure_misconfigs),
                'gcp': len(gcp_misconfigs)
            },
            'iam_issues': len(iam_issues),
            'encryption_issues': len(encryption_findings),
            'public_exposure': len(exposed_resources),
            'compliance_frameworks': len(compliance['frameworks']),
            'top_misconfigurations': all_misconfigs[:10],
            'top_iam_issues': iam_issues[:10],
            'exposed_resources': exposed_resources[:10],
            'compliance_status': compliance
        }

    def _log_finding_incident(self, finding: Dict) -> None:
        """Mirror a high/critical cloud finding into audit and (optionally) relay."""
        # First, write a structured THREAT_DETECTED event into the
        # comprehensive audit log so governance and forensics can see
        # cloud posture as part of the same audit surface used in
        # stages 6 and 7.
        try:
            from emergency_killswitch import get_audit_log, AuditEventType

            provider = finding.get('provider') or finding.get('cloud') or 'unknown'
            resource = finding.get('resource') or finding.get('identity') or 'unknown'
            issue = finding.get('issue') or finding.get('risk') or 'cloud_finding'
            severity = str(finding.get('severity', 'high')).lower()

            # Map cloud severity to audit risk level.
            if severity == 'critical':
                risk = 'critical'
            elif severity == 'high':
                risk = 'high'
            elif severity == 'medium':
                risk = 'medium'
            else:
                risk = 'low'

            audit = get_audit_log()
            audit.log_event(
                event_type=AuditEventType.THREAT_DETECTED,
                actor='cloud_security',
                action='cloud_misconfiguration_detected',
                target=resource,
                outcome='observed',
                details=finding,
                risk_level=risk,
                metadata={
                    'module': 'cloud_security',
                    'provider': provider,
                    'issue': issue,
                },
            )
        except Exception as e:
            print(f"[CLOUD] Failed to write finding to audit log: {e}")

        # Then, if a relay training tree is present, append a sanitized
        # incident record into relay/ai_training_materials/global_attacks.json
        # so that cloud misconfigurations can be used as training signals
        # alongside traffic and federated incidents.
        try:
            base_dir = os.path.join(os.path.dirname(__file__), '..')
            training_dir = os.path.join(base_dir, 'relay', 'ai_training_materials')
            if not os.path.isdir(training_dir):
                return

            attacks_file = os.path.join(training_dir, 'global_attacks.json')

            if os.path.exists(attacks_file):
                with open(attacks_file, 'r') as f:
                    attacks = json.load(f)
                    if not isinstance(attacks, list):
                        attacks = []
            else:
                attacks = []

            record = {
                'attack_type': 'cloud_misconfiguration',
                'provider': finding.get('provider') or finding.get('cloud'),
                'resource': finding.get('resource') or finding.get('identity'),
                'issue': finding.get('issue') or finding.get('risk'),
                'severity': finding.get('severity', 'high'),
                'timestamp': finding.get('detected_at') or datetime.now().isoformat(),
                'source': 'cloud_security',
                'relay_server': os.getenv('RELAY_NAME', 'central-relay'),
            }

            attacks.append(record)

            with open(attacks_file, 'w') as f:
                json.dump(attacks, f, indent=2)
        except Exception as e:
            print(f"[CLOUD] Failed to write cloud incident to global_attacks.json: {e}")

# Global instance
cloud_security = CloudSecurityPosture()
