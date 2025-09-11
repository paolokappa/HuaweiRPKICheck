#!/usr/bin/env python3
"""
Outlook-compatible Professional Email Templates for RPKI Monitor
Designed for maximum compatibility and readability
"""

from datetime import datetime
from typing import Dict, List

def generate_outlook_email(subject_type: str, analysis: Dict, sessions: List[Dict], config: Dict) -> tuple:
    """
    Generate Outlook-compatible professional email template
    
    Args:
        subject_type: 'alert', 'recovery', or 'status'
        analysis: Analysis dictionary with session states
        sessions: List of session dictionaries
        config: Configuration dictionary
    
    Returns:
        tuple: (subject, html_body)
    """
    
    # Determine status with new color logic
    # Count problematic sessions
    problem_count = len(analysis.get('idle', [])) + len(analysis.get('negotiation', [])) + len(analysis.get('syn', []))
    total_sessions = analysis.get('total', 0)
    
    if analysis['healthy']:
        # Blue for normal/healthy state
        status_color = '#0066CC'
        status_text = '✓ All Systems Operational'
        header_bg = '#0066CC'
        status_detail = 'All RPKI sessions are functioning normally'
    elif problem_count >= total_sessions and total_sessions > 0:
        # Red when ALL sessions are down
        status_color = '#D13438'
        status_text = '✗ Critical - All Sessions Down'
        header_bg = '#D13438'
        status_detail = 'All RPKI sessions are experiencing issues'
    elif len(analysis.get('skip_reset', [])) > 0 or len(analysis.get('routinator_issues', [])) > 0:
        # Red for Routinator issues or persistent problems
        status_color = '#D13438'
        status_text = '✗ Critical Issues'
        header_bg = '#D13438'
        status_detail = ', '.join(analysis['issues'][:2])
    else:
        # Yellow for warning (some sessions with problems)
        status_color = '#FFA500'
        status_text = '⚠ Issues Detected'
        header_bg = '#FFA500'
        status_detail = ', '.join(analysis['issues'][:2])
    
    # Generate subject
    timestamp = datetime.now().strftime('%H:%M')
    if subject_type == 'alert':
        subject = f"Huawei NetEngine - RPKI Alert: {status_detail[:60]} [{timestamp}]"
    elif subject_type == 'recovery':
        subject = f"Huawei NetEngine - RPKI Recovery: Sessions Restored [{timestamp}]"
    else:
        subject = "Huawei NetEngine - RPKI Sessions Status Report"
    
    # Calculate percentages
    total = analysis['total']
    established = len(analysis['established'])
    issues = len(analysis['idle']) + len(analysis['negotiation']) + len(analysis['syn'])
    health_pct = int((established / total * 100)) if total > 0 else 0
    
    # Generate session rows
    session_rows = ""
    for session in sessions:
        # Determine row color based on state
        if session['state'].lower() == 'established':
            row_bg = '#E6F2FF'
            state_color = '#0066CC'
            state_symbol = '●'
        elif session['state'].lower() in ['negotiation', 'syn']:
            row_bg = '#FFF4E6'
            state_color = '#FF8C00'
            state_symbol = '○'
        else:
            row_bg = '#FFF0F0'
            state_color = '#D13438'
            state_symbol = '○'
        
        # Format records
        records = session.get('records', '0/0')
        
        session_rows += f"""
        <tr style="background-color: {row_bg};">
            <td style="padding: 8px; border: 1px solid #D4D4D4; font-family: Consolas, monospace; font-size: 12px;">
                {session['ip']}
            </td>
            <td style="padding: 8px; border: 1px solid #D4D4D4; color: {state_color}; font-weight: bold; font-size: 12px;">
                <span style="color: {state_color};">{state_symbol}</span> {session['state']}
            </td>
            <td style="padding: 8px; border: 1px solid #D4D4D4; font-size: 12px;">
                {session.get('age', 'N/A')}
            </td>
            <td style="padding: 8px; border: 1px solid #D4D4D4; font-family: Consolas, monospace; font-size: 12px;">
                {records}
            </td>
        </tr>
        """
    
    # Routinator issues section
    routinator_section = ""
    if analysis.get('routinator_issues'):
        routinator_section = f"""
        <table cellpadding="0" cellspacing="0" style="width: 100%; margin-top: 15px;">
            <tr>
                <td style="background-color: #FFF0F0; border: 1px solid #D13438; padding: 10px;">
                    <div style="color: #D13438; font-weight: bold; font-size: 13px; margin-bottom: 5px;">
                        ⚠ Routinator Service Issues Detected
                    </div>
                    <div style="color: #333333; font-size: 12px; line-height: 18px;">
                        {"<br>".join(analysis['routinator_issues'])}
                    </div>
                </td>
            </tr>
        </table>
        """
    
    # Action required section
    action_section = ""
    if analysis.get('need_reset'):
        action_section = f"""
        <table cellpadding="0" cellspacing="0" style="width: 100%; margin-top: 15px;">
            <tr>
                <td style="background-color: #FFF4E6; border: 1px solid #FF8C00; padding: 10px;">
                    <div style="color: #FF8C00; font-weight: bold; font-size: 13px; margin-bottom: 5px;">
                        🔄 Automatic Reset Scheduled
                    </div>
                    <div style="color: #333333; font-size: 12px;">
                        Sessions to reset: {', '.join(analysis['need_reset'])}
                    </div>
                </td>
            </tr>
        </table>
        """
    
    # Build HTML body
    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <!--[if mso]>
        <noscript>
            <xml>
                <o:OfficeDocumentSettings>
                    <o:AllowPNG/>
                    <o:PixelsPerInch>96</o:PixelsPerInch>
                </o:OfficeDocumentSettings>
            </xml>
        </noscript>
        <![endif]-->
    </head>
    <body style="margin: 0; padding: 0; background-color: #F5F5F5; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;">
        <table cellpadding="0" cellspacing="0" border="0" width="100%" style="background-color: #F5F5F5;">
            <tr>
                <td align="center" style="padding: 20px 10px;">
                    <table cellpadding="0" cellspacing="0" border="0" width="600" style="background-color: #FFFFFF; border: 1px solid #D4D4D4;">
                        
                        <!-- Header -->
                        <tr>
                            <td style="background-color: {header_bg}; padding: 20px 25px;">
                                <table cellpadding="0" cellspacing="0" border="0" width="100%">
                                    <tr>
                                        <td style="color: #FFFFFF; font-size: 20px; font-weight: bold;">
                                            Huawei NetEngine - RPKI Session Monitor
                                        </td>
                                        <td align="right" style="color: #FFFFFF; font-size: 11px;">
                                            GOLINE SA
                                        </td>
                                    </tr>
                                </table>
                            </td>
                        </tr>
                        
                        <!-- Status Bar -->
                        <tr>
                            <td style="background-color: #F8F8F8; padding: 15px 25px; border-bottom: 1px solid #E1E1E1;">
                                <table cellpadding="0" cellspacing="0" border="0" width="100%">
                                    <tr>
                                        <td>
                                            <span style="color: {status_color}; font-size: 16px; font-weight: bold;">
                                                {status_text}
                                            </span>
                                            <div style="color: #666666; font-size: 12px; margin-top: 3px;">
                                                {status_detail}
                                            </div>
                                        </td>
                                        <td align="right" style="color: #666666; font-size: 11px;">
                                            {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}
                                        </td>
                                    </tr>
                                </table>
                            </td>
                        </tr>
                        
                        <!-- Metrics Summary -->
                        <tr>
                            <td style="padding: 20px 25px;">
                                <table cellpadding="0" cellspacing="0" border="0" width="100%" style="background-color: #F8F8F8;">
                                    <tr>
                                        <td width="25%" align="center" style="padding: 15px; border-right: 1px solid #E1E1E1;">
                                            <div style="color: #333333; font-size: 24px; font-weight: bold;">{total}</div>
                                            <div style="color: #666666; font-size: 11px; margin-top: 3px;">TOTAL</div>
                                        </td>
                                        <td width="25%" align="center" style="padding: 15px; border-right: 1px solid #E1E1E1;">
                                            <div style="color: #0066CC; font-size: 24px; font-weight: bold;">{established}</div>
                                            <div style="color: #666666; font-size: 11px; margin-top: 3px;">ESTABLISHED</div>
                                        </td>
                                        <td width="25%" align="center" style="padding: 15px; border-right: 1px solid #E1E1E1;">
                                            <div style="color: {'#FF8C00' if issues > 0 else '#666666'}; font-size: 24px; font-weight: bold;">{issues}</div>
                                            <div style="color: #666666; font-size: 11px; margin-top: 3px;">ISSUES</div>
                                        </td>
                                        <td width="25%" align="center" style="padding: 15px;">
                                            <div style="color: {status_color}; font-size: 24px; font-weight: bold;">{health_pct}%</div>
                                            <div style="color: #666666; font-size: 11px; margin-top: 3px;">HEALTH</div>
                                        </td>
                                    </tr>
                                </table>
                            </td>
                        </tr>
                        
                        <!-- Session Details -->
                        <tr>
                            <td style="padding: 0 25px 20px 25px;">
                                <div style="color: #333333; font-size: 14px; font-weight: bold; margin-bottom: 10px;">
                                    Session Details
                                </div>
                                <table cellpadding="0" cellspacing="0" border="0" width="100%" style="border-collapse: collapse;">
                                    <tr style="background-color: #E1E1E1;">
                                        <th style="padding: 8px; border: 1px solid #D4D4D4; text-align: left; font-size: 11px; font-weight: bold;">
                                            SESSION IP
                                        </th>
                                        <th style="padding: 8px; border: 1px solid #D4D4D4; text-align: left; font-size: 11px; font-weight: bold;">
                                            STATUS
                                        </th>
                                        <th style="padding: 8px; border: 1px solid #D4D4D4; text-align: left; font-size: 11px; font-weight: bold;">
                                            AGE
                                        </th>
                                        <th style="padding: 8px; border: 1px solid #D4D4D4; text-align: left; font-size: 11px; font-weight: bold;">
                                            IPv4/IPv6
                                        </th>
                                    </tr>
                                    {session_rows}
                                </table>
                                
                                {routinator_section}
                                {action_section}
                            </td>
                        </tr>
                        
                        <!-- Footer -->
                        <tr>
                            <td style="background-color: #F8F8F8; padding: 20px 25px; border-top: 2px solid #E1E1E1;">
                                <table cellpadding="0" cellspacing="0" border="0" width="100%">
                                    <tr>
                                        <td style="text-align: center;">
                                            <div style="color: #0066CC; font-size: 14px; font-weight: bold; margin-bottom: 8px;">
                                                GOLINE SA
                                            </div>
                                            <div style="color: #666666; font-size: 12px; line-height: 18px;">
                                                Via Croce Campagna 2, 6855 Stabio, Switzerland<br>
                                                <span style="color: #0066CC;">Email: soc@goline.ch</span> | Tel: +41 91 2607650
                                            </div>
                                            <div style="color: #0066CC; font-size: 11px; margin-top: 10px; padding-top: 10px; border-top: 1px solid #E1E1E1;">
                                                <strong>HuaweiRPKICheck v3.6</strong>
                                            </div>
                                        </td>
                                    </tr>
                                </table>
                            </td>
                        </tr>
                        
                    </table>
                </td>
            </tr>
        </table>
    </body>
    </html>
    """
    
    return subject, html_body