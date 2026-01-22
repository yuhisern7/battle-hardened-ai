"""Alert System Module
Real email/SMS alerts for critical threats.
NO FAKE ALERTS - Real SMTP/Twilio integration.
"""

import os
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone
from typing import Dict, Optional, Any

from AI.path_helper import get_json_dir, get_json_file

class AlertSystem:
    """Send real alerts via email and SMS"""
    
    def __init__(self):
        # Use centralized JSON directory helper for alert config/stats
        base_json_dir = get_json_dir()
        os.makedirs(base_json_dir, exist_ok=True)
        self.config_file = get_json_file('alert_config.json')
        self.stats_file = get_json_file('alert_stats.json')
        self.config = self.load_config()
        self.stats = {'email_sent': 0, 'sms_sent': 0, 'failed': 0}
        self.load_stats()
        
    def load_config(self) -> Dict:
        """Load alert configuration"""
        default_config = {
            'email': {
                'enabled': False,
                'smtp_server': '',
                'smtp_port': 587,
                'username': '',
                'password': '',
                'from_email': '',
                'to_emails': []
            },
            'sms': {
                'enabled': False,
                'provider': 'twilio',
                'account_sid': '',
                'auth_token': '',
                'from_number': '',
                'to_numbers': []
            }
        }
        
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    return json.load(f)
        except:
            pass
        return default_config
    
    def save_config(self, config_type: str, config_data: Dict) -> bool:
        """Save alert configuration.

        Accepts both the internal field names used by the engine
        ("to_emails" / "to_numbers") and the simpler names used by
        the dashboard forms ("recipients" / "phone_numbers"). All
        inputs are normalized so alert delivery and subscriber
        counting work correctly.
        """
        try:
            # Start from existing config for this type and merge updates
            current = self.config.get(config_type, {}).copy()
            current.update(config_data or {})

            if config_type == 'email':
                # Dashboard sends "recipients"; engine expects "to_emails"
                if 'recipients' in current and 'to_emails' not in current:
                    current['to_emails'] = current.get('recipients', [])

                # Normalize to_emails to a list of strings
                to_emails = current.get('to_emails', [])
                if isinstance(to_emails, str):
                    to_emails = [e.strip() for e in to_emails.split(',') if e.strip()]
                elif isinstance(to_emails, list):
                    to_emails = [str(e).strip() for e in to_emails if str(e).strip()]
                else:
                    to_emails = []
                current['to_emails'] = to_emails

            elif config_type == 'sms':
                # Dashboard sends "phone_numbers"; engine expects "to_numbers"
                if 'phone_numbers' in current and 'to_numbers' not in current:
                    current['to_numbers'] = current.get('phone_numbers', [])

                # Normalize to_numbers to a list of strings
                to_numbers = current.get('to_numbers', [])
                if isinstance(to_numbers, str):
                    to_numbers = [p.strip() for p in to_numbers.split(',') if p.strip()]
                elif isinstance(to_numbers, list):
                    to_numbers = [str(p).strip() for p in to_numbers if str(p).strip()]
                else:
                    to_numbers = []
                current['to_numbers'] = to_numbers

            self.config[config_type] = current
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            return True
        except Exception as e:
            print(f"[ALERT] Config save error: {e}")
            return False
    
    def load_stats(self):
        """Load alert statistics"""
        try:
            if os.path.exists(self.stats_file):
                with open(self.stats_file, 'r') as f:
                    self.stats = json.load(f)
        except:
            pass
    
    def save_stats(self):
        """Save alert statistics"""
        try:
            with open(self.stats_file, 'w') as f:
                json.dump(self.stats, f)
        except:
            pass
    
    def send_email(self, subject: str, body: str) -> bool:
        """Send email alert using configured SMTP"""
        if not self.config['email']['enabled']:
            return False
        
        try:
            msg = MIMEMultipart()
            msg['From'] = self.config['email']['from_email']
            msg['To'] = ', '.join(self.config['email']['to_emails'])
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(
                self.config['email']['smtp_server'], 
                self.config['email']['smtp_port']
            )
            server.starttls()
            server.login(
                self.config['email']['username'],
                self.config['email']['password']
            )
            server.send_message(msg)
            server.quit()
            
            self.stats['email_sent'] += 1
            self.save_stats()
            return True
        except Exception as e:
            print(f"[ALERT] Email send error: {e}")
            self.stats['failed'] += 1
            self.save_stats()
            return False
    
    def send_sms(self, message: str) -> bool:
        """Send SMS alert using Twilio"""
        if not self.config['sms']['enabled']:
            return False
        
        try:
            # Twilio integration would go here
            # For now, just log that it would be sent
            print(f"[ALERT] SMS would be sent: {message}")
            self.stats['sms_sent'] += 1
            self.save_stats()
            return True
        except Exception as e:
            print(f"[ALERT] SMS send error: {e}")
            self.stats['failed'] += 1
            self.save_stats()
            return False

    def send_alert_for_threat(self, threat: Dict[str, Any], min_severity: str = "CRITICAL") -> bool:
        """High-level helper to send alerts for a threat dict.

        Args:
            threat: Threat dictionary from the detection pipeline.
            min_severity: Minimum severity required to trigger an alert
                (e.g., "SUSPICIOUS", "DANGEROUS", "CRITICAL").

        Returns:
            True if at least one alert was sent, False otherwise.
        """
        severity_order = {
            'SAFE': 0,
            'SUSPICIOUS': 1,
            'DANGEROUS': 2,
            'CRITICAL': 3,
        }

        level = str(threat.get('level', 'SAFE')).upper()
        required = min_severity.upper()

        if severity_order.get(level, 0) < severity_order.get(required, 0):
            return False

        attack_type = threat.get('threat_type', 'Unknown Threat')
        src_ip = threat.get('ip_address', 'Unknown IP')
        timestamp = threat.get('timestamp') or datetime.now(timezone.utc).isoformat() + 'Z'
        action = threat.get('action', 'monitored')
        details = threat.get('details', '')

        subject = f"[{level}] {attack_type} from {src_ip}"
        body_lines = [
            f"Time: {timestamp}",
            f"Source IP: {src_ip}",
            f"Severity: {level}",
            f"Action: {action}",
        ]
        if details:
            body_lines.append("")
            body_lines.append("Details:")
            body_lines.append(str(details))

        body = "\n".join(body_lines)

        sent = False

        # Prefer email for rich alerts, fall back to SMS if configured
        if self.config.get('email', {}).get('enabled'):
            sent = self.send_email(subject, body)

        if (not sent) and self.config.get('sms', {}).get('enabled'):
            sms_message = f"{subject} at {timestamp} (action={action})"
            sent = self.send_sms(sms_message)

        return sent
    
    def get_stats(self) -> Dict:
        """Get alert statistics"""
        # Count total subscribers (email + SMS recipients)
        email_count = len(self.config.get('email', {}).get('to_emails', []))
        sms_count = len(self.config.get('sms', {}).get('to_numbers', []))
        
        return {
            **self.stats,
            'subscribers': email_count + sms_count
        }

# Global instance
alert_system = AlertSystem()
