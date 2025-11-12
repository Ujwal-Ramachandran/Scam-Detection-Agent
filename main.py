"""
Main Orchestration Script for Phishing Detection System
"""

import logging
from datetime import datetime

from sms_agent import SMSAgent
from url_agent import URLAgent
from content_agent import ContentAgent
from metadata_agent import MetadataAgent
# from behavior_agent import BehaviorAgent
from report_agent import ReportAgent

from detection_context import DetectionContext
from json_storage import JSONStorage
from location_utils import get_host_location, get_phone_info

import config


LOGGER_NAME = "phishing_detector"
LOG_FILE = "phishing_detection.log"


def setup_logging():
    """Configure logging for the phishing detection system."""
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        file_handler = logging.FileHandler(LOG_FILE, mode="a", encoding="utf-8")
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        )

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter("%(message)s"))

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

    return logger

class PhishingDetector:
    def __init__(self):
        # Initialize all agents
        self.sms_agent = SMSAgent()
        self.url_agent = URLAgent()
        self.content_agent = ContentAgent()
        self.metadata_agent = MetadataAgent()
        # self.behavior_agent = BehaviorAgent()
        self.report_agent = ReportAgent()
        
        # Initialize storage
        self.storage = JSONStorage()
        
        if not logging.getLogger(LOGGER_NAME).handlers:
            setup_logging()
        self.logger = logging.getLogger(LOGGER_NAME)
    
    def detect(self, sms_text, sender):
        """
        Main detection pipeline using Context Object
        
        Args:
            sms_text (str): SMS message text
            sender (str): Sender ID/number
        
        Returns:
            dict: Final verdict and analysis results
        """
        self.logger.info("=" * 80)
        self.logger.info("PHISHING DETECTION PIPELINE STARTED")
        self.logger.info("=" * 80)
        
        # Create detection context
        context = DetectionContext()
        context.sender_message = sms_text
        context.sender_mobile_number = sender
        context.message_timestamp = datetime.now()
        
        # Get location information
        self.logger.info("\n[System] Gathering location information...")
        context.host_location = get_host_location()
        
        if sender:
            phone_info = get_phone_info(sender)
            if phone_info:
                context.sender_country = phone_info.get('country')
                context.sender_carrier = phone_info.get('carrier')
                context.sender_phone_valid = phone_info.get('is_valid')
        
        # Layer 1: SMS Analysis
        context = self.sms_agent.analyze(context)
        
        # If safe with high confidence, exit early
        sms_result = context.agent_results.get('SMSAgent', {})
        if sms_result.get('verdict') == 'safe' and sms_result.get('confidence', 0) > config.CONFIDENCE_THRESHOLD_HIGH:
            context.final_verdict = 'safe'
            context.final_confidence = sms_result['confidence']
            context.detected_by = 'SMS Analysis'
            
            self.logger.info("")
            self.logger.info("=" * 80)
            self.logger.info("FINAL VERDICT: SAFE (No suspicious content detected)")
            self.logger.info("=" * 80)
            
            # Save context and generate report
            self.storage.save_detection(context)
            report = self.report_agent.generate_report(context)
            self.report_agent.save_report_to_file(report, context)
            
            return self._create_final_report(context, report)
        
        # If no URLs found, exit
        if not context.urls_found:
            context.final_verdict = 'safe'
            context.final_confidence = sms_result.get('confidence', 0.9)
            context.detected_by = 'SMS Analysis'
            
            self.logger.info("")
            self.logger.info("=" * 80)
            self.logger.info("FINAL VERDICT: SAFE (No URLs to analyze)")
            self.logger.info("=" * 80)
            
            # Save context and generate report
            self.storage.save_detection(context)
            report = self.report_agent.generate_report(context)
            self.report_agent.save_report_to_file(report, context)
            
            return self._create_final_report(context, report)
        
        # Analyze each URL
        for url in context.urls_found:
            self.logger.info("")
            self.logger.info("=" * 80)
            self.logger.info("ANALYZING URL: %s", url)
            self.logger.info("=" * 80)
            
            # Layer 2: URL Analysis
            context = self.url_agent.analyze(context, url)
            
            url_result = context.agent_results.get('URLAgent', {})
            if url_result.get('verdict') == 'phishing' and url_result.get('confidence', 0) > config.CONFIDENCE_THRESHOLD_HIGH:
                context.final_verdict = 'phishing'
                context.final_confidence = url_result['confidence']
                context.detected_by = 'URL Analysis'
                
                self.logger.info("")
                self.logger.info("=" * 80)
                self.logger.info("FINAL VERDICT: PHISHING (Detected at URL layer)")
                self.logger.info("=" * 80)
                
                # Save context and generate report
                self.storage.save_detection(context)
                report = self.report_agent.generate_report(context)
                self.report_agent.save_report_to_file(report, context)
                
                return self._create_final_report(context, report)
            
            # Layer 3: Content Analysis
            context = self.content_agent.analyze(context, url)
            
            content_result = context.agent_results.get('ContentAgent', {})
            if content_result.get('verdict') == 'phishing' and content_result.get('confidence', 0) > config.CONFIDENCE_THRESHOLD_HIGH:
                context.final_verdict = 'phishing'
                context.final_confidence = content_result['confidence']
                context.detected_by = 'Content Analysis'
                
                self.logger.info("")
                self.logger.info("=" * 80)
                self.logger.info("FINAL VERDICT: PHISHING (Detected at Content layer)")
                self.logger.info("=" * 80)
                
                # Save context and generate report
                self.storage.save_detection(context)
                report = self.report_agent.generate_report(context)
                self.report_agent.save_report_to_file(report, context)
                
                return self._create_final_report(context, report)
            
            # Layer 4: Metadata Analysis
            context = self.metadata_agent.analyze(context, url)
            
            metadata_result = context.agent_results.get('MetadataAgent', {})
            if metadata_result.get('verdict') == 'phishing' and metadata_result.get('confidence', 0) > config.CONFIDENCE_THRESHOLD_HIGH:
                context.final_verdict = 'phishing'
                context.final_confidence = metadata_result['confidence']
                context.detected_by = 'Metadata Analysis'
                
                self.logger.info("")
                self.logger.info("=" * 80)
                self.logger.info("FINAL VERDICT: PHISHING (Detected at Metadata layer)")
                self.logger.info("=" * 80)
                
                # Save context and generate report
                self.storage.save_detection(context)
                report = self.report_agent.generate_report(context)
                self.report_agent.save_report_to_file(report, context)
                
                return self._create_final_report(context, report)
            
            ### BEHAVIOR AGENT
            # Layer 5: Behavioral Analysis (only if still uncertain)
            # This is the most resource-intensive, so only run if needed
            # if self._needs_behavioral_analysis(context):
            #     behavior_result = self.behavior_agent.analyze({'url': url})
            #     context.set_agent_result('Behavioral Analysis', behavior_result)
            #     
            #     if behavior_result['verdict'] == 'phishing' and behavior_result['confidence'] > config.CONFIDENCE_THRESHOLD_HIGH:
            #         context.final_verdict = 'phishing'
            #         context.final_confidence = behavior_result['confidence']
            #         context.detected_by = 'Behavioral Analysis'
            #         
            #         self.logger.info("")
            #         self.logger.info("=" * 80)
            #         self.logger.info("FINAL VERDICT: PHISHING (Detected at Behavioral layer)")
            #         self.logger.info("=" * 80)
            #         
            #         self.storage.save_detection(context)
            #         report = self.report_agent.generate_report(context)
            #         
            #         return self._create_final_report(context, report)
        
        # If we've gone through all layers without high-confidence phishing detection
        final_verdict_data = self._aggregate_results(context)
        
        context.final_verdict = final_verdict_data['verdict']
        context.final_confidence = final_verdict_data['confidence']
        context.detected_by = 'Aggregated Analysis'
        
        self.logger.info("")
        self.logger.info("=" * 80)
        self.logger.info(
            "FINAL VERDICT: %s (Aggregated from all layers)",
            context.final_verdict.upper(),
        )
        self.logger.info("Confidence: %.2f", context.final_confidence)
        self.logger.info("=" * 80)
        
        # Save context and generate report
        self.storage.save_detection(context)
        report = self.report_agent.generate_report(context)
        self.report_agent.save_report_to_file(report, context)
        
        return self._create_final_report(context, report)
    
    def _needs_behavioral_analysis(self, context):
        """Determine if behavioral analysis is needed based on previous results"""
        # Run behavioral analysis if we have uncertain verdicts
        for agent_name, result in context.agent_results.items():
            if result['verdict'] == 'uncertain' or (result['verdict'] == 'phishing' and result['confidence'] < config.CONFIDENCE_THRESHOLD_HIGH):
                return True
        return False
    
    def _aggregate_results(self, context):
        """Aggregate results from all layers to make final decision with weighted voting"""
        # Define weights for each agent (higher weight = more important)
        agent_weights = {
            'SMSAgent': 1.0,
            'URLAgent': 1.5,
            'ContentAgent': 1.2,
            'MetadataAgent': 1.0,
            # 'Behavioral Analysis': 2.0  ## Highest weight as it's most comprehensive
        }
        
        phishing_votes = 0
        safe_votes = 0
        total_weights = 0
        
        for agent_name, result in context.agent_results.items():
            # Get weight for this agent (default to 1.0 if not found)
            weight = agent_weights.get(agent_name, 1.0)
            weighted_confidence = result['confidence'] * weight
            
            if result['verdict'] == 'phishing':
                phishing_votes += weighted_confidence
                total_weights += weight
            elif result['verdict'] == 'safe':
                safe_votes += weighted_confidence
                total_weights += weight
            # Uncertain verdicts don't contribute to either side
        
        # Calculate weighted verdict
        total_votes = phishing_votes + safe_votes
        
        if total_votes == 0:
            # All uncertain
            return {
                'verdict': 'uncertain',
                'confidence': 0.5
            }
        
        if phishing_votes > safe_votes:
            verdict = 'phishing'
            # Normalize confidence by total votes to get 0-1 range
            confidence = phishing_votes / total_votes if total_votes > 0 else 0.0
        elif safe_votes > phishing_votes:
            verdict = 'safe'
            # Normalize confidence by total votes to get 0-1 range
            confidence = safe_votes / total_votes if total_votes > 0 else 0.0
        else:
            verdict = 'uncertain'
            confidence = 0.5
        
        return {
            'verdict': verdict,
            'confidence': confidence
        }
    
    def _create_final_report(self, context, report):
        """Create final report combining context and generated report"""
        return {
            'verdict': context.final_verdict,
            'confidence': context.final_confidence,
            'detected_by': context.detected_by,
            'detection_id': context.detection_id,
            'risk_score': context.risk_score,
            'context': context,
            'detailed_report': report
        }
    
    def print_detailed_report(self, final_result):
        """Print detailed analysis report"""
        context = final_result['context']
        report = final_result['detailed_report']
        
        self.logger.info("")
        self.logger.info("=" * 80)
        self.logger.info("DETAILED ANALYSIS REPORT")
        self.logger.info("=" * 80)
        
        # Print agent results
        for agent_name, result in context.agent_results.items():
            self.logger.info("")
            self.logger.info("[%s]", agent_name)
            self.logger.info("  Verdict: %s", result['verdict'])
            self.logger.info("  Confidence: %.2f", result['confidence'])
            self.logger.info("  Reasoning: %s", result['reasoning'])
        
        # Print risk analysis
        self.logger.info("")
        self.logger.info("=" * 80)
        self.logger.info("RISK ANALYSIS")
        self.logger.info("=" * 80)
        self.logger.info("Risk Score: %d/100", context.risk_score)
        self.logger.info("Red Flags: %d", len(context.red_flags))
        self.logger.info("Green Flags: %d", len(context.green_flags))
        
        if context.red_flags:
            self.logger.info("\nSuspicious Indicators:")
            for flag in context.red_flags:
                self.logger.info("  • [%s] %s (+%d points)", flag['agent'], flag['reason'], flag['points'])
        
        if context.green_flags:
            self.logger.info("\nLegitimate Indicators:")
            for flag in context.green_flags:
                self.logger.info("  • [%s] %s", flag['agent'], flag['reason'])
        
        # Print final verdict
        self.logger.info("")
        self.logger.info("=" * 80)
        self.logger.info("FINAL VERDICT: %s", context.final_verdict.upper())
        self.logger.info("Confidence: %.2f", context.final_confidence)
        self.logger.info("Detected by: %s", context.detected_by)
        self.logger.info("Detection ID: %s", context.detection_id)
        self.logger.info("=" * 80)
        
        # Print recommendations
        self.logger.info("")
        self.logger.info("RECOMMENDATIONS:")
        for rec in report['recommendations']:
            self.logger.info(rec)

def main():
    """Main entry point"""
    logger = setup_logging()
    logger.info("")
    logger.info("=" * 80)
    logger.info("SMS PHISHING DETECTION SYSTEM")
    logger.info("=" * 80)
    logger.info("")
    
    # Get user input
    print("Enter SMS details:")
    sender = input("Sender ID/Number: ").strip()
    print("\nEnter SMS message :")
    
    lines = []
    while True:
        line = input()
        if line == "" and lines and lines[-1] == "":
            break
        lines.append(line)
    
    sms_text = "\n".join(lines[:-1])  # Remove last empty line
    
    print("\nAnalyzing SMS for phishing indicators...\n")
    # Run detection
    detector = PhishingDetector()
    result = detector.detect(sms_text, sender)
    
    # Print detailed report
    detector.print_detailed_report(result)
    
    # Recommendation
    logger.info("")
    logger.info("=" * 80)
    logger.info("FINAL RECOMMENDATION:")
    logger.info("=" * 80)
    if result['verdict'] == 'phishing':
        logger.warning("⚠️  DO NOT click any links or provide any information.")
        logger.warning("⚠️  Delete this message immediately.")
        logger.warning("⚠️  Report this as phishing to your service provider.")
    elif result['verdict'] == 'safe':
        logger.info("✓  This message appears to be safe.")
        logger.info("✓  However, always verify sender identity before clicking links.")
    else:
        logger.warning("⚠️  Unable to determine with high confidence.")
        logger.warning("⚠️  Exercise caution and verify sender through official channels.")

if __name__ == "__main__":
    main()