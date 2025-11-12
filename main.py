"""
Main Orchestration Script for Phishing Detection System
"""

from sms_agent import SMSAgent
from url_agent import URLAgent
from content_agent import ContentAgent
from metadata_agent import MetadataAgent
from behavior_agent import BehaviorAgent
import config

class PhishingDetector:
    def __init__(self):
        # Initialize all agents
        self.sms_agent = SMSAgent()
        self.url_agent = URLAgent()
        self.content_agent = ContentAgent()
        self.metadata_agent = MetadataAgent()
        self.behavior_agent = BehaviorAgent()
        
        self.results = []
    
    def detect(self, sms_text, sender):
        """
        Main detection pipeline
        
        Args:
            sms_text (str): SMS message text
            sender (str): Sender ID/number
        
        Returns:
            dict: Final verdict and analysis results
        """
        print("="*80)
        print("PHISHING DETECTION PIPELINE STARTED")
        print("="*80)
        
        # Layer 1: SMS Analysis
        sms_result = self.sms_agent.analyze({
            'sms_text': sms_text,
            'sender': sender
        })
        self.results.append(('SMS Analysis', sms_result))
        
        # If safe with high confidence, exit early
        if sms_result['verdict'] == 'safe' and sms_result['confidence'] > config.CONFIDENCE_THRESHOLD_HIGH:
            print("\n" + "="*80)
            print("FINAL VERDICT: SAFE (No suspicious content detected)")
            print("="*80)
            return self._create_final_report('safe', sms_result['confidence'], 'SMS Analysis')
        
        # If no URLs found, exit
        if not sms_result['urls_found']:
            print("\n" + "="*80)
            print("FINAL VERDICT: SAFE (No URLs to analyze)")
            print("="*80)
            return self._create_final_report('safe', sms_result['confidence'], 'SMS Analysis')
        
        # Analyze each URL
        for url in sms_result['urls_found']:
            print(f"\n{'='*80}")
            print(f"ANALYZING URL: {url}")
            print(f"{'='*80}")
            
            # Layer 2: URL Analysis
            url_result = self.url_agent.analyze({'url': url})
            self.results.append(('URL Analysis', url_result))
            
            if url_result['verdict'] == 'phishing' and url_result['confidence'] > config.CONFIDENCE_THRESHOLD_HIGH:
                print("\n" + "="*80)
                print("FINAL VERDICT: PHISHING (Detected at URL layer)")
                print("="*80)
                return self._create_final_report('phishing', url_result['confidence'], 'URL Analysis')
            
            # Layer 3: Content Analysis
            content_result = self.content_agent.analyze({'url': url})
            self.results.append(('Content Analysis', content_result))
            
            if content_result['verdict'] == 'phishing' and content_result['confidence'] > config.CONFIDENCE_THRESHOLD_HIGH:
                print("\n" + "="*80)
                print("FINAL VERDICT: PHISHING (Detected at Content layer)")
                print("="*80)
                return self._create_final_report('phishing', content_result['confidence'], 'Content Analysis')
            
            # Layer 4: Metadata Analysis
            metadata_result = self.metadata_agent.analyze({'url': url})
            self.results.append(('Metadata Analysis', metadata_result))
            
            if metadata_result['verdict'] == 'phishing' and metadata_result['confidence'] > config.CONFIDENCE_THRESHOLD_HIGH:
                print("\n" + "="*80)
                print("FINAL VERDICT: PHISHING (Detected at Metadata layer)")
                print("="*80)
                return self._create_final_report('phishing', metadata_result['confidence'], 'Metadata Analysis')
            
            # Layer 5: Behavioral Analysis (only if still uncertain)
            # This is the most resource-intensive, so only run if needed
            if self._needs_behavioral_analysis():
                behavior_result = self.behavior_agent.analyze({'url': url})
                self.results.append(('Behavioral Analysis', behavior_result))
                
                if behavior_result['verdict'] == 'phishing' and behavior_result['confidence'] > config.CONFIDENCE_THRESHOLD_HIGH:
                    print("\n" + "="*80)
                    print("FINAL VERDICT: PHISHING (Detected at Behavioral layer)")
                    print("="*80)
                    return self._create_final_report('phishing', behavior_result['confidence'], 'Behavioral Analysis')
        
        # If we've gone through all layers without high-confidence phishing detection
        final_verdict = self._aggregate_results()
        print("\n" + "="*80)
        print(f"FINAL VERDICT: {final_verdict['verdict'].upper()} (Aggregated from all layers)")
        print(f"Confidence: {final_verdict['confidence']:.2f}")
        print("="*80)
        
        return final_verdict
    
    def _needs_behavioral_analysis(self):
        """Determine if behavioral analysis is needed based on previous results"""
        # Run behavioral analysis if we have uncertain verdicts
        for layer_name, result in self.results:
            if result['verdict'] == 'uncertain' or (result['verdict'] == 'phishing' and result['confidence'] < config.CONFIDENCE_THRESHOLD_HIGH):
                return True
        return False
    
    def _aggregate_results(self):
        """Aggregate results from all layers to make final decision"""
        phishing_votes = 0
        safe_votes = 0
        total_confidence = 0
        
        for layer_name, result in self.results:
            if result['verdict'] == 'phishing':
                phishing_votes += result['confidence']
            elif result['verdict'] == 'safe':
                safe_votes += result['confidence']
            total_confidence += result['confidence']
        
        # Calculate weighted verdict
        if phishing_votes > safe_votes:
            verdict = 'phishing'
            confidence = phishing_votes / len(self.results)
        elif safe_votes > phishing_votes:
            verdict = 'safe'
            confidence = safe_votes / len(self.results)
        else:
            verdict = 'uncertain'
            confidence = 0.5
        
        return self._create_final_report(verdict, confidence, 'Aggregated Analysis')
    
    def _create_final_report(self, verdict, confidence, detected_by):
        """Create final report"""
        return {
            'verdict': verdict,
            'confidence': confidence,
            'detected_by': detected_by,
            'all_results': self.results
        }
    
    def print_detailed_report(self, final_result):
        """Print detailed analysis report"""
        print("\n" + "="*80)
        print("DETAILED ANALYSIS REPORT")
        print("="*80)
        
        for layer_name, result in final_result['all_results']:
            print(f"\n[{layer_name}]")
            print(f"  Verdict: {result['verdict']}")
            print(f"  Confidence: {result['confidence']:.2f}")
            print(f"  Reasoning: {result['reasoning']}")
        
        print("\n" + "="*80)
        print(f"FINAL VERDICT: {final_result['verdict'].upper()}")
        print(f"Confidence: {final_result['confidence']:.2f}")
        print(f"Detected by: {final_result['detected_by']}")
        print("="*80)

def main():
    """Main entry point"""
    print("\n" + "="*80)
    print("SMS PHISHING DETECTION SYSTEM")
    print("="*80 + "\n")
    
    # Get user input
    print("Enter SMS details:")
    sender = input("Sender ID/Number: ").strip()
    print("\nEnter SMS message (press Enter twice when done):")
    
    lines = []
    while True:
        line = input()
        if line == "" and lines and lines[-1] == "":
            break
        lines.append(line)
    
    sms_text = "\n".join(lines[:-1])  # Remove last empty line
    
    # Run detection
    detector = PhishingDetector()
    result = detector.detect(sms_text, sender)
    
    # Print detailed report
    detector.print_detailed_report(result)
    
    # Recommendation
    print("\nRECOMMENDATION:")
    if result['verdict'] == 'phishing':
        print("⚠️  DO NOT click any links or provide any information.")
        print("⚠️  Delete this message immediately.")
        print("⚠️  Report this as phishing to your service provider.")
    elif result['verdict'] == 'safe':
        print("✓  This message appears to be safe.")
        print("✓  However, always verify sender identity before clicking links.")
    else:
        print("⚠️  Unable to determine with high confidence.")
        print("⚠️  Exercise caution and verify sender through official channels.")

if __name__ == "__main__":
    main()
