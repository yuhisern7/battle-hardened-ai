#!/usr/bin/env python3
"""
Enterprise Security Report Generator
Generates professional HTML reports for executive and security teams
"""

def generate_html_report(report: dict, current_time) -> str:
    """Generate professional HTML report for enterprise clients"""
    meta = report['report_metadata']
    exec_summary = report['executive_summary']
    threat_stats = report['threat_statistics']
    attacker_intel = report['attacker_intelligence']
    ai_insights = report['ai_ml_insights']
    threat_sources = report['threat_intelligence_sources']
    
    # Generate severity chart data
    severity = exec_summary.get('severity_breakdown', {})
    
    # Generate top threat types
    top_threats = list(threat_stats['threat_type_breakdown'].items())[:10]
    
    # Generate top countries
    top_countries = list(threat_stats['geographic_distribution'].items())[:10]
    
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{meta['report_title']}</title>
    <style>
        @media print {{
            .no-print {{ display: none; }}
            body {{ background: white; }}
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #0b1020 0%, #1a2642 100%);
            color: #2c3e50;
            line-height: 1.6;
            padding: 2rem;
        }}
        
        .report-container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 10px 60px rgba(0, 0, 0, 0.3);
            border-radius: 12px;
            overflow: hidden;
        }}
        
        .report-header {{
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 3rem 2rem;
            text-align: center;
            border-bottom: 5px solid #3498db;
        }}
        
        .report-header h1 {{
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
            font-weight: 700;
        }}
        
        .report-header .subtitle {{
            font-size: 1.1rem;
            opacity: 0.9;
            margin-bottom: 1.5rem;
        }}
        
        .report-meta {{
            display: flex;
            justify-content: center;
            gap: 2rem;
            flex-wrap: wrap;
            font-size: 0.9rem;
            opacity: 0.8;
        }}
        
        .report-meta-item {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        
        .report-body {{
            padding: 3rem 2rem;
        }}
        
        .section {{
            margin-bottom: 3rem;
            page-break-inside: avoid;
        }}
        
        .section-title {{
            font-size: 1.8rem;
            color: #2c3e50;
            margin-bottom: 1.5rem;
            padding-bottom: 0.75rem;
            border-bottom: 3px solid #3498db;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}
        
        .executive-summary {{
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            padding: 2rem;
            border-radius: 8px;
            border-left: 5px solid #3498db;
        }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin: 1.5rem 0;
        }}
        
        .stat-card {{
            background: white;
            padding: 1.5rem;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            text-align: center;
        }}
        
        .stat-card .label {{
            font-size: 0.85rem;
            color: #7f8c8d;
            margin-bottom: 0.5rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .stat-card .value {{
            font-size: 2.5rem;
            font-weight: 700;
            color: #2c3e50;
        }}
        
        .stat-card.critical .value {{ color: #e74c3c; }}
        .stat-card.warning .value {{ color: #f39c12; }}
        .stat-card.success .value {{ color: #27ae60; }}
        .stat-card.info .value {{ color: #3498db; }}
        
        .risk-indicator {{
            background: white;
            padding: 2rem;
            border-radius: 8px;
            margin: 1.5rem 0;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        
        .risk-score {{
            text-align: center;
            margin-bottom: 1.5rem;
        }}
        
        .risk-score .score {{
            font-size: 4rem;
            font-weight: 700;
            margin: 1rem 0;
        }}
        
        .risk-score .posture {{
            font-size: 1.5rem;
            font-weight: 600;
            padding: 0.5rem 1rem;
            border-radius: 6px;
            display: inline-block;
        }}
        
        .recommendations {{
            background: #fff3cd;
            border-left: 5px solid #ffc107;
            padding: 1.5rem;
            border-radius: 8px;
            margin-top: 1.5rem;
        }}
        
        .recommendations h3 {{
            color: #856404;
            margin-bottom: 1rem;
        }}
        
        .recommendations ul {{
            list-style: none;
        }}
        
        .recommendations li {{
            padding: 0.5rem 0;
            padding-left: 1.5rem;
            position: relative;
        }}
        
        .recommendations li:before {{
            content: "⚠️";
            position: absolute;
            left: 0;
        }}
        
        .data-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 1.5rem 0;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }}
        
        .data-table thead {{
            background: linear-gradient(135deg, #34495e 0%, #2c3e50 100%);
            color: white;
        }}
        
        .data-table th {{
            padding: 1rem;
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85rem;
            letter-spacing: 0.5px;
        }}
        
        .data-table td {{
            padding: 1rem;
            border-bottom: 1px solid #ecf0f1;
        }}
        
        .data-table tbody tr:hover {{
            background: #f8f9fa;
        }}
        
        .data-table tbody tr:last-child td {{
            border-bottom: none;
        }}
        
        .badge {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        
        .badge.critical {{ background: #fee; color: #c0392b; }}
        .badge.dangerous {{ background: #ffe; color: #e67e22; }}
        .badge.suspicious {{ background: #fff3cd; color: #856404; }}
        .badge.safe {{ background: #d4edda; color: #155724; }}
        
        .chart-container {{
            background: white;
            padding: 1.5rem;
            border-radius: 8px;
            margin: 1.5rem 0;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        
        .bar-chart {{
            margin: 1rem 0;
        }}
        
        .bar-chart-item {{
            display: flex;
            align-items: center;
            margin-bottom: 1rem;
        }}
        
        .bar-chart-label {{
            width: 150px;
            font-size: 0.9rem;
            font-weight: 500;
        }}
        
        .bar-chart-bar {{
            flex: 1;
            height: 30px;
            background: linear-gradient(90deg, #3498db 0%, #2980b9 100%);
            border-radius: 4px;
            position: relative;
            margin: 0 1rem;
        }}
        
        .bar-chart-value {{
            width: 60px;
            text-align: right;
            font-weight: 600;
            color: #2c3e50;
        }}
        
        .report-footer {{
            background: #f8f9fa;
            padding: 2rem;
            text-align: center;
            border-top: 1px solid #dee2e6;
            color: #7f8c8d;
            font-size: 0.9rem;
        }}
        
        .print-button {{
            background: linear-gradient(135deg, #3498db 0%, #2980b9 100%);
            color: white;
            border: none;
            padding: 1rem 2rem;
            font-size: 1rem;
            border-radius: 6px;
            cursor: pointer;
            margin: 1rem;
            box-shadow: 0 4px 12px rgba(52, 152, 219, 0.3);
            transition: all 0.3s;
        }}
        
        .print-button:hover {{
            transform: translateY(-2px);
            box-shadow: 0 6px 16px rgba(52, 152, 219, 0.4);
        }}
    </style>
</head>
<body>
    <div class="report-container">
        <div class="report-header">
            <h1>🛡️ {meta['report_title']}</h1>
            <div class="subtitle">{meta['system_name']}</div>
            <div class="report-meta">
                <div class="report-meta-item">
                    <span>📅</span>
                    <span>Generated: {current_time.strftime('%B %d, %Y at %H:%M %Z')}</span>
                </div>
                <div class="report-meta-item">
                    <span>🌍</span>
                    <span>Timezone: {meta['timezone']}</span>
                </div>
                <div class="report-meta-item">
                    <span>📊</span>
                    <span>Period: {meta['report_period']}</span>
                </div>
                <div class="report-meta-item">
                    <span>🔢</span>
                    <span>Version: {meta['report_version']}</span>
                </div>
            </div>
            <div style="margin-top: 2rem;" class="no-print">
                <button class="print-button" onclick="window.print()">🖨️ Print Report</button>
            </div>
        </div>
        
        <div class="report-body">
            <!-- Executive Summary -->
            <div class="section">
                <h2 class="section-title">📋 Executive Summary</h2>
                <div class="executive-summary">
                    <div class="summary-grid">
                        <div class="stat-card critical">
                            <div class="label">Total Threats</div>
                            <div class="value">{exec_summary['total_threats_detected']:,}</div>
                        </div>
                        <div class="stat-card warning">
                            <div class="label">Unique Attackers</div>
                            <div class="value">{exec_summary['unique_attacker_ips']:,}</div>
                        </div>
                        <div class="stat-card info">
                            <div class="label">Blocked IPs</div>
                            <div class="value">{exec_summary['blocked_ips']:,}</div>
                        </div>
                    </div>
                    
                    <div class="risk-indicator">
                        <div class="risk-score">
                            <div style="font-size: 1.2rem; color: #7f8c8d; margin-bottom: 0.5rem;">SECURITY RISK SCORE</div>
                            <div class="score" style="color: {exec_summary['posture_color']}">{exec_summary['risk_score']}/100</div>
                            <div class="posture" style="background: {exec_summary['posture_color']}20; color: {exec_summary['posture_color']}; border: 2px solid {exec_summary['posture_color']}">
                                {exec_summary['security_posture']}
                            </div>
                        </div>
                        
                        <div style="margin-top: 2rem;">
                            <h4 style="margin-bottom: 1rem; color: #2c3e50;">🔍 Critical Findings</h4>
                            <ul style="list-style: none;">
                                {''.join(f'<li style="padding: 0.5rem 0; padding-left: 1.5rem; position: relative;"><span style="position: absolute; left: 0;">•</span> {finding}</li>' for finding in exec_summary['critical_findings'])}
                            </ul>
                        </div>
                    </div>
                    
                    <div class="recommendations">
                        <h3>📌 Priority Recommendations</h3>
                        <ul>
                            {''.join(f'<li>{rec}</li>' for rec in exec_summary['recommendations'])}
                        </ul>
                    </div>
                </div>
            </div>
            
            <!-- Threat Statistics -->
            <div class="section">
                <h2 class="section-title">📊 Threat Analysis</h2>
                
                <div class="chart-container">
                    <h3 style="margin-bottom: 1rem;">Severity Breakdown</h3>
                    <div class="bar-chart">
'''    
    
    # Add severity bars
    severity_data = threat_stats['severity_breakdown']
    max_severity = max(severity_data.values()) if severity_data else 1
    
    for level, badge_class in [('CRITICAL', 'critical'), ('DANGEROUS', 'dangerous'), ('SUSPICIOUS', 'suspicious'), ('SAFE', 'safe')]:
        value = severity_data.get(level, 0)
        width_percent = (value / max_severity * 100) if max_severity > 0 else 0
        colors = {'critical': '#e74c3c', 'dangerous': '#e67e22', 'suspicious': '#f39c12', 'safe': '#27ae60'}
        html += f'''
                        <div class="bar-chart-item">
                            <div class="bar-chart-label">{level}</div>
                            <div class="bar-chart-bar" style="width: {width_percent}%; background: linear-gradient(90deg, {colors[badge_class]} 0%, {colors[badge_class]}dd 100%);"></div>
                            <div class="bar-chart-value">{value:,}</div>
                        </div>
'''
    
    html += '''
                    </div>
                </div>
                
                <div class="chart-container">
                    <h3 style="margin-bottom: 1rem;">Top Threat Types</h3>
                    <div class="bar-chart">
'''
    
    # Add threat type bars
    max_threats = max([count for _, count in top_threats]) if top_threats else 1
    for threat_type, count in top_threats:
        width_percent = (count / max_threats * 100) if max_threats > 0 else 0
        html += f'''
                        <div class="bar-chart-item">
                            <div class="bar-chart-label">{threat_type[:25]}</div>
                            <div class="bar-chart-bar" style="width: {width_percent}%;"></div>
                            <div class="bar-chart-value">{count:,}</div>
                        </div>
'''
    
    html += f'''
                    </div>
                </div>
            </div>
            
            <!-- Top Attackers -->
            <div class="section">
                <h2 class="section-title">🎯 Top Threat Actors</h2>
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Rank</th>
                            <th>IP Address</th>
                            <th>Attacks</th>
                            <th>Countries</th>
                            <th>Threat Types</th>
                            <th>Severity</th>
                        </tr>
                    </thead>
                    <tbody>
'''
    
    for idx, attacker in enumerate(attacker_intel['top_attackers'][:15], 1):
        countries = ', '.join(attacker['countries'][:2])
        threat_types = ', '.join(list(attacker['threat_types'])[:3])
        severity_counts = {}
        for s in attacker['severity']:
            severity_counts[s] = severity_counts.get(s, 0) + 1
        top_severity = max(severity_counts, key=severity_counts.get) if severity_counts else 'SUSPICIOUS'
        
        html += f'''
                        <tr>
                            <td><strong>#{idx}</strong></td>
                            <td><code>{attacker['ip']}</code></td>
                            <td><strong>{attacker['count']:,}</strong></td>
                            <td>{countries}</td>
                            <td style="font-size: 0.85rem;">{threat_types}</td>
                            <td><span class="badge {top_severity.lower()}">{top_severity}</span></td>
                        </tr>
'''
    
    html += f'''
                    </tbody>
                </table>
            </div>
            
            <!-- Geographic Distribution -->
            <div class="section">
                <h2 class="section-title">🌍 Geographic Distribution</h2>
                <div class="chart-container">
                    <div class="bar-chart">
'''
    
    max_country = max([count for _, count in top_countries]) if top_countries else 1
    for country, count in top_countries:
        width_percent = (count / max_country * 100) if max_country > 0 else 0
        html += f'''
                        <div class="bar-chart-item">
                            <div class="bar-chart-label">{country}</div>
                            <div class="bar-chart-bar" style="width: {width_percent}%; background: linear-gradient(90deg, #9b59b6 0%, #8e44ad 100%);"></div>
                            <div class="bar-chart-value">{count:,}</div>
                        </div>
'''
    
    html += f'''
                    </div>
                </div>
            </div>
            
            <!-- AI/ML Insights -->
            <div class="section">
                <h2 class="section-title">🤖 AI/ML Intelligence</h2>
                <div class="summary-grid">
                    <div class="stat-card info">
                        <div class="label">ML Status</div>
                        <div class="value" style="font-size: 1.5rem;">{ai_insights['ml_status']}</div>
                    </div>
                    <div class="stat-card success">
                        <div class="label">Training Samples</div>
                        <div class="value">{ai_insights['training_samples']:,}</div>
                    </div>
                    <div class="stat-card">
                        <div class="label">Prediction Accuracy</div>
                        <div class="value">{ai_insights['prediction_accuracy']:.1f}%</div>
                    </div>
                </div>
                
                <div style="background: #e8f5e9; padding: 1.5rem; border-radius: 8px; margin-top: 1.5rem; border-left: 5px solid #27ae60;">
                    <h4 style="color: #155724; margin-bottom: 1rem;">🎓 Threat Intelligence Sources</h4>
                    <ul style="list-style: none;">
                        <li style="padding: 0.5rem 0;">{'✅' if threat_sources['virustotal_enabled'] else '❌'} <strong>VirusTotal API:</strong> {'Active - 70+ security vendors' if threat_sources['virustotal_enabled'] else 'Not configured'}</li>
                        <li style="padding: 0.5rem 0;">{'✅' if threat_sources['abuseipdb_enabled'] else '❌'} <strong>AbuseIPDB:</strong> {'Active - Community blacklist' if threat_sources['abuseipdb_enabled'] else 'Not configured'}</li>
                        <li style="padding: 0.5rem 0;">✅ <strong>ExploitDB:</strong> {threat_sources['exploitdb_signatures']:,} exploit signatures loaded</li>
                        <li style="padding: 0.5rem 0;">✅ <strong>Honeypots:</strong> {threat_sources['honeypot_attacks']:,} attacker interactions logged</li>
                    </ul>
                </div>
            </div>
            
            <!-- VPN/Tor Intelligence -->
            <div class="section">
                <h2 class="section-title">🔓 De-Anonymization Intelligence</h2>
                <div class="summary-grid">
                    <div class="stat-card warning">
                        <div class="label">VPN Users Detected</div>
                        <div class="value">{attacker_intel['vpn_tor_usage']['total_vpn_users']:,}</div>
                    </div>
                    <div class="stat-card warning">
                        <div class="label">Tor Users Detected</div>
                        <div class="value">{attacker_intel['vpn_tor_usage']['total_tor_users']:,}</div>
                    </div>
                    <div class="stat-card success">
                        <div class="label">Real IPs Revealed</div>
                        <div class="value">{attacker_intel['vpn_tor_usage']['real_ips_revealed']:,}</div>
                    </div>
                    <div class="stat-card info">
                        <div class="label">Proxy Chains</div>
                        <div class="value">{attacker_intel['fingerprint_tracking']['proxy_chains_detected']:,}</div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="report-footer">
            <p><strong>Enterprise Security Threat Intelligence System</strong></p>
            <p>This report is confidential and intended for authorized personnel only.</p>
            <p>Generated by AI-Powered Network Security System v2.0</p>
            <p style="margin-top: 1rem; font-size: 0.85rem;">© {current_time.year} · All Rights Reserved</p>
        </div>
    </div>
</body>
</html>
'''
    
    return html
