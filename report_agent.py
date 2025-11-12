"""
Report Agent - Generates comprehensive reports from detection context
"""

from detection_context import DetectionContext
from json_storage import JSONStorage
from typing import Dict, List
from datetime import datetime


class ReportAgent:
    """
    Generates detailed forensic reports from detection context and historical data.
    Replaces the Behavior Agent with intelligent analysis of logs and patterns.
    """
    
    def __init__(self, storage: JSONStorage = None):
        """
        Initialize Report Agent
        
        Args:
            storage: JSONStorage instance for accessing historical detections
        """
        self.name = "ReportAgent"
        self.storage = storage or JSONStorage()
    
    def generate_report(self, context: DetectionContext) -> Dict:
        """
        Generate comprehensive forensic report
        
        Args:
            context: DetectionContext with all analysis results
            
        Returns:
            Dict containing detailed report
        """
        print(f"\n[{self.name}] Generating comprehensive report...")
        
        report = {
            'detection_id': context.detection_id,
            'timestamp': context.timestamp.isoformat(),
            'executive_summary': self._create_executive_summary(context),
            'risk_analysis': self._analyze_risk_factors(context),
            'historical_patterns': self._find_similar_patterns(context),
            'forensic_timeline': self._create_timeline(context),
            'recommendations': self._generate_recommendations(context),
            'confidence_explanation': self._explain_confidence(context),
            'statistics': self._calculate_statistics(context)
        }
        
        print(f"[{self.name}] Report generated successfully")
        return report
    
    def _create_executive_summary(self, context: DetectionContext) -> str:
        """Create human-readable executive summary"""
        verdict = context.final_verdict.upper() if context.final_verdict else 'UNKNOWN'
        confidence = context.final_confidence * 100
        
        summary_lines = []
        summary_lines.append(f"**VERDICT: {verdict}** (Confidence: {confidence:.1f}%)")
        summary_lines.append("")
        
        if context.final_verdict == 'phishing':
            summary_lines.append("⚠️ **CRITICAL ALERT: This message is highly likely to be a phishing scam.**")
            summary_lines.append("")
            summary_lines.append(f"Risk Score: {context.risk_score}/100")
            summary_lines.append(f"Suspicious Indicators Found: {len(context.red_flags)}")
            summary_lines.append(f"Legitimate Indicators Found: {len(context.green_flags)}")
            
        elif context.final_verdict == 'uncertain':
            summary_lines.append("⚠️ **CAUTION: This message shows suspicious characteristics.**")
            summary_lines.append("")
            summary_lines.append("The system cannot definitively classify this message. ")
            summary_lines.append("Exercise extreme caution and verify through official channels.")
            
        else:  # safe
            summary_lines.append("✅ **This message appears to be legitimate.**")
            summary_lines.append("")
            summary_lines.append(f"Legitimate Indicators Found: {len(context.green_flags)}")
            summary_lines.append("However, always verify sender identity before taking action.")
        
        return "\n".join(summary_lines)
    
    def _analyze_risk_factors(self, context: DetectionContext) -> Dict:
        """Break down risk score by category and agent"""
        categories = {
            'sms_indicators': [],
            'url_indicators': [],
            'content_indicators': [],
            'metadata_indicators': []
        }
        
        # Categorize red flags by agent
        for flag in context.red_flags:
            agent = flag['agent']
            if 'SMS' in agent:
                categories['sms_indicators'].append(flag)
            elif 'URL' in agent:
                categories['url_indicators'].append(flag)
            elif 'Content' in agent:
                categories['content_indicators'].append(flag)
            elif 'Metadata' in agent:
                categories['metadata_indicators'].append(flag)
        
        # Calculate scores per category
        risk_breakdown = {
            'total_risk_score': context.risk_score,
            'categories': {}
        }
        
        for cat_name, flags in categories.items():
            if flags:
                risk_breakdown['categories'][cat_name] = {
                    'count': len(flags),
                    'total_points': sum(f['points'] for f in flags),
                    'indicators': [f['reason'] for f in flags]
                }
        
        return risk_breakdown
    
    def _find_similar_patterns(self, context: DetectionContext) -> List[Dict]:
        """Find similar scams in historical data"""
        similar_patterns = []
        
        try:
            # Check for repeat sender
            if context.sender_mobile_number:
                by_sender = self.storage.search_by_sender(context.sender_mobile_number)
                if len(by_sender) > 1:  # More than just current detection
                    similar_patterns.append({
                        'type': 'repeat_sender',
                        'count': len(by_sender) - 1,
                        'message': f'This sender has sent {len(by_sender) - 1} previous messages',
                        'severity': 'high' if len(by_sender) > 3 else 'medium'
                    })
            
            # Check for same URLs
            if context.urls_found:
                for url in context.urls_found:
                    by_url = self.storage.search_by_url(url)
                    if len(by_url) > 1:
                        similar_patterns.append({
                            'type': 'known_url',
                            'count': len(by_url) - 1,
                            'message': f'URL "{url}" has been seen {len(by_url) - 1} times before',
                            'severity': 'high'
                        })
        
        except Exception as e:
            print(f"[{self.name}] Error finding similar patterns: {e}")
        
        return similar_patterns
    
    def _create_timeline(self, context: DetectionContext) -> List[Dict]:
        """Create chronological timeline of detection events"""
        timeline = []
        
        # Add red flags
        for flag in context.red_flags:
            timeline.append({
                'timestamp': flag['timestamp'],
                'type': 'risk_detected',
                'agent': flag['agent'],
                'description': flag['reason'],
                'points': flag['points'],
                'severity': 'high' if flag['points'] >= 20 else 'medium' if flag['points'] >= 10 else 'low'
            })
        
        # Add green flags
        for flag in context.green_flags:
            timeline.append({
                'timestamp': flag['timestamp'],
                'type': 'positive_indicator',
                'agent': flag['agent'],
                'description': flag['reason'],
                'severity': 'info'
            })
        
        # Sort by timestamp
        timeline.sort(key=lambda x: x['timestamp'])
        
        return timeline
    
    def _generate_recommendations(self, context: DetectionContext) -> List[str]:
        """Generate actionable recommendations based on verdict"""
        recommendations = []
        
        if context.final_verdict == 'phishing':
            recommendations.extend([
                "🚨 DO NOT click any links in this message",
                "🚨 DO NOT provide any personal information, passwords, or OTPs",
                "🚨 DO NOT call any phone numbers mentioned in the message",
                "🗑️ Delete this message immediately",
                "📞 Report to your mobile carrier as spam/phishing",
                "🔒 If you already clicked links or provided information:",
                "   - Change your passwords immediately",
                "   - Monitor your bank accounts for suspicious activity",
                "   - Contact your bank/service provider",
                "   - Consider filing a police report"
            ])
            
            if context.sender_mobile_number:
                recommendations.append(f"🚫 Block sender: {context.sender_mobile_number}")
            
            if context.urls_found:
                recommendations.append(f"⚠️ Malicious URLs detected: {', '.join(context.urls_found[:3])}")
        
        elif context.final_verdict == 'uncertain':
            recommendations.extend([
                "⚠️ Exercise extreme caution with this message",
                "📞 Verify sender through official channels (use contact info from official website)",
                "🔍 Do not trust caller ID or sender name - they can be spoofed",
                "❌ Do not provide sensitive information via SMS",
                "🌐 If message mentions a company, visit their official website directly (do not click links)",
                "⏰ Take your time - legitimate organizations will not pressure you",
                "💬 If in doubt, contact the organization directly using official contact methods"
            ])
        
        else:  # safe
            recommendations.extend([
                "✅ Message appears legitimate based on current analysis",
                "⚠️ Always verify sender identity before taking action",
                "🔒 Never share passwords, OTPs, or PINs via SMS",
                "🌐 When in doubt, visit official websites directly (don't click links)",
                "📞 If message requests urgent action, verify through official channels"
            ])
        
        return recommendations
    
    def _explain_confidence(self, context: DetectionContext) -> str:
        """Explain how confidence score was calculated"""
        explanation_lines = []
        explanation_lines.append("Confidence Calculation:")
        explanation_lines.append("")
        
        for agent_name, result in context.agent_results.items():
            verdict = result.get('verdict', 'unknown')
            confidence = result.get('confidence', 0.0)
            explanation_lines.append(
                f"- {agent_name}: {verdict.upper()} (confidence: {confidence:.2f})"
            )
        
        explanation_lines.append("")
        explanation_lines.append(f"Final weighted confidence: {context.final_confidence:.2f}")
        explanation_lines.append(f"Determined by: {context.detected_by}")
        
        return "\n".join(explanation_lines)
    
    def _calculate_statistics(self, context: DetectionContext) -> Dict:
        """Calculate statistical metrics"""
        stats = {
            'total_agents_run': len(context.agent_results),
            'total_red_flags': len(context.red_flags),
            'total_green_flags': len(context.green_flags),
            'risk_score': context.risk_score,
            'urls_analyzed': len(context.urls_found),
            'message_length': len(context.sender_message) if context.sender_message else 0
        }
        
        # Add location info if available
        if context.host_location:
            stats['host_country'] = context.host_location.get('country', 'Unknown')
        
        if context.sender_country:
            stats['sender_country'] = context.sender_country
        
        return stats
    
    def print_report(self, report: Dict):
        """Print formatted report to console"""
        print("\n" + "=" * 80)
        print("PHISHING DETECTION REPORT")
        print("=" * 80)
        
        print("\n" + report['executive_summary'])
        
        print("\n" + "-" * 80)
        print("RISK ANALYSIS")
        print("-" * 80)
        risk = report['risk_analysis']
        print(f"Total Risk Score: {risk['total_risk_score']}/100")
        
        for cat_name, cat_data in risk.get('categories', {}).items():
            print(f"\n{cat_name.replace('_', ' ').title()}:")
            for indicator in cat_data['indicators']:
                print(f"  • {indicator}")
        
        if report['historical_patterns']:
            print("\n" + "-" * 80)
            print("HISTORICAL PATTERNS")
            print("-" * 80)
            for pattern in report['historical_patterns']:
                print(f"• {pattern['message']} (Severity: {pattern['severity']})")
        
        print("\n" + "-" * 80)
        print("RECOMMENDATIONS")
        print("-" * 80)
        for rec in report['recommendations']:
            print(rec)
        
        print("\n" + "=" * 80)

    def save_report_to_file(self, report: Dict, context: DetectionContext, reports_dir: str = 'reports') -> str:
        """
        Save formatted report to a text file
        
        Args:
            report: Generated report dictionary
            context: DetectionContext with detection data
            reports_dir: Directory to save report files
            
        Returns:
            Path to saved report file
        """
        from pathlib import Path
        
        # Create reports directory if it doesn't exist
        Path(reports_dir).mkdir(exist_ok=True)
        
        # Create filename with timestamp
        timestamp_str = context.timestamp.strftime('%Y%m%d_%H%M%S')
        filename = f"phishing_detection_{timestamp_str}.log"
        filepath = Path(reports_dir) / filename
        
        # Format and write report
        with open(filepath, 'w', encoding='utf-8') as f:
            # Header
            f.write("=" * 80 + "\n")
            f.write("PHISHING DETECTION REPORT\n")
            f.write("=" * 80 + "\n")
            f.write(f"Detection ID: {context.detection_id}\n")
            f.write(f"Timestamp: {context.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Sender: {context.sender_mobile_number}\n")
            f.write("=" * 80 + "\n\n")
            
            # Executive Summary
            f.write(report['executive_summary'] + "\n\n")
            
            # Risk Analysis
            f.write("-" * 80 + "\n")
            f.write("RISK ANALYSIS\n")
            f.write("-" * 80 + "\n")
            risk = report['risk_analysis']
            f.write(f"Total Risk Score: {risk['total_risk_score']}/100\n\n")
            
            for cat_name, cat_data in risk.get('categories', {}).items():
                f.write(f"{cat_name.replace('_', ' ').title()}:\n")
                for indicator in cat_data['indicators']:
                    f.write(f"  • {indicator}\n")
                f.write("\n")
            
            # Historical Patterns
            if report['historical_patterns']:
                f.write("-" * 80 + "\n")
                f.write("HISTORICAL PATTERNS\n")
                f.write("-" * 80 + "\n")
                for pattern in report['historical_patterns']:
                    f.write(f"• {pattern['message']} (Severity: {pattern['severity']})\n")
                f.write("\n")
            
            # Forensic Timeline
            if report['forensic_timeline']:
                f.write("-" * 80 + "\n")
                f.write("FORENSIC TIMELINE\n")
                f.write("-" * 80 + "\n")
                for event in report['forensic_timeline']:
                    f.write(f"[{event['timestamp']}] {event['type'].upper()}\n")
                    f.write(f"  Agent: {event['agent']}\n")
                    f.write(f"  Description: {event['description']}\n")
                    if 'points' in event:
                        f.write(f"  Risk Points: +{event['points']}\n")
                    f.write("\n")
            
            # Recommendations
            f.write("-" * 80 + "\n")
            f.write("RECOMMENDATIONS\n")
            f.write("-" * 80 + "\n")
            for rec in report['recommendations']:
                f.write(rec + "\n")
            f.write("\n")
            
            # Confidence Explanation
            f.write("-" * 80 + "\n")
            f.write("CONFIDENCE ANALYSIS\n")
            f.write("-" * 80 + "\n")
            f.write(report['confidence_explanation'] + "\n\n")
            
            # Statistics
            f.write("-" * 80 + "\n")
            f.write("STATISTICS\n")
            f.write("-" * 80 + "\n")
            stats = report['statistics']
            for key, value in stats.items():
                f.write(f"{key.replace('_', ' ').title()}: {value}\n")
            
            # Footer
            f.write("\n" + "=" * 80 + "\n")
            f.write("END OF REPORT\n")
            f.write("=" * 80 + "\n")
        
        print(f"[{self.name}] Report saved to: {filepath}")
        return str(filepath)