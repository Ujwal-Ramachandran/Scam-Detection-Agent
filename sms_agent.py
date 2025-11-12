"""
SMS Agent - Analyzes SMS text and sender information
"""

import utils
import config
from detection_context import DetectionContext


class SMSAgent:
    def __init__(self):
        self.name = "SMSAgent"
    
    def analyze(self, context: DetectionContext) -> DetectionContext:
        """
        Analyze SMS for phishing indicators
        
        Args:
            context: DetectionContext with sender_message and sender_mobile_number
        
        Returns:
            Updated DetectionContext with analysis results
        """
        sms_text = context.sender_message or ''
        sender = context.sender_mobile_number or 'Unknown'
        
        print(f"\n[{self.name}] Analyzing SMS...")
        print(f"Sender: {sender}")
        print(f"Message: {sms_text[:100]}...")
        
        # Extract URLs from SMS
        urls_found = utils.extract_urls_from_text(sms_text)
        context.urls_found = urls_found
        
        # If no URLs found, likely safe
        if not urls_found:
            result = {
                'verdict': 'safe',
                'confidence': 0.9,
                'reasoning': 'No URLs detected in SMS message',
                'urls_found': [],
                'sender': sender
            }
            
            # Add to context
            context.set_agent_result(self.name, result)
            context.add_green_flag('No URLs detected in message', self.name)
            
            print(f"[{self.name}] Verdict: safe (confidence: 0.90)")
            return context
        
        # Prepare prompt for LLM
        prompt = f"""Analyze this SMS message for phishing indicators.
        All entities in promotional, unsolicited, or unknown SMS messages (numbers, links, apps, accounts, websites, customer centers, etc.) must be flagged as points of scam, regardless of whether they belong to legitimate companies.
        Input Format:
        SMS Sender: {sender}
        SMS Text: {sms_text}
        URLs Found: {', '.join(urls_found)}

        Risk Assessment:
        Extract ALL entities/resources mentioned (numbers, links, apps, accounts, websites, service centers)
        If ANY entity is present in promotional/unsolicited/unknown SMS, flag it as a point of scam
        Check for trust exploitation: impersonation, urgency, emotional triggers, security bypass
        Recognize deceptive patterns: generic greetings, grammar errors, too-good-to-be-true offers

        Provide your analysis in this exact format:
        Verdict: safe/phishing
        Confidence: <0.0-1.0>
        Point of Scam: <Exact entity or "NONE DETECTED">
        Reasoning: <Brief explanation, 1-2 sentences>
        If the confidence score is under 0.4 for phishing or safe then return uncertain with reasoning..
        The reasoning should summarize the key factors that influenced your decision. It should not be very big, maximum 1 paragraph. Remember the output should only contain the fields requested(Verdict, Confidence, Reasoning), no additional text.
        """
        
        response = utils.query_llm(prompt)
        
        if response:
            result = utils.parse_agent_response(response)
            result['urls_found'] = urls_found
            result['sender'] = sender
            
            # Add to context
            context.set_agent_result(self.name, result)
            
            # Add risk/green flags based on verdict
            if result['verdict'] == 'phishing':
                risk_points = int(result['confidence'] * 30)  # Max 30 points from SMS
                context.add_risk(risk_points, result['reasoning'], self.name)
            elif result['verdict'] == 'safe':
                context.add_green_flag(result['reasoning'], self.name)
            
            print(f"[{self.name}] Verdict: {result['verdict']} (confidence: {result['confidence']:.2f})")
            print(f"[{self.name}] Reasoning: {result['reasoning']}")
            
            return context
        else:
            # Fallback if LLM fails
            result = {
                'verdict': 'uncertain',
                'confidence': 0.5,
                'reasoning': 'Unable to analyze with LLM, but URLs detected',
                'urls_found': urls_found,
                'sender': sender
            }
            
            context.set_agent_result(self.name, result)
            context.add_risk(10, 'URLs detected but LLM analysis failed', self.name)
            
            return context