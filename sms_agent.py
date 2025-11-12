"""
SMS Agent - Analyzes SMS text and sender information
"""

import utils
import config

class SMSAgent:
    def __init__(self):
        self.name = "SMSAgent"
    
    def analyze(self, data):
        """
        Analyze SMS for phishing indicators
        
        Args:
            data (dict): {
                'sms_text': str,
                'sender': str
            }
        
        Returns:
            dict: {
                'verdict': 'safe'|'phishing'|'suspicious',
                'confidence': float,
                'reasoning': str,
                'urls_found': list,
                'sender': str
            }
        """
        sms_text = data.get('sms_text', '')
        sender = data.get('sender', 'Unknown')
        
        print(f"\n[{self.name}] Analyzing SMS...")
        print(f"Sender: {sender}")
        print(f"Message: {sms_text[:100]}...")
        
        # Extract URLs from SMS
        urls_found = utils.extract_urls_from_text(sms_text)
        
        # If no URLs found, likely safe
        if not urls_found:
            return {
                'verdict': 'safe',
                'confidence': 0.9,
                'reasoning': 'No URLs detected in SMS message',
                'urls_found': [],
                'sender': sender
            }
        
        # Prepare prompt for LLM
        prompt = f"""
You are an expert system designed to identify scams in SMS messages. A point of scam is any specific entity, resource, or element the recipient is directed to interact with, which could lead to fraud, financial loss, or security compromise.

Strict Policy
All entities in promotional, unsolicited, or unknown SMS messages (numbers, links, apps, accounts, websites, customer centers, etc.) must be flagged as points of scam, regardless of whether they belong to legitimate companies.

Input Format:
SMS Sender: {sender}
SMS Text: {sms_text}
URLs Found: {', '.join(urls_found)}

Analysis Framework:

Risk Assessment (Strict Mode)
Extract ALL entities/resources mentioned (numbers, links, apps, accounts, websites, service centers)
If ANY entity is present in promotional/unsolicited/unknown SMS, flag it as a point of scam
Check for trust exploitation: impersonation, urgency, emotional triggers, security bypass
Recognize deceptive patterns: generic greetings, grammar errors, too-good-to-be-true offers

Remember there are 4 outputs.

Output Format
Verdict: [safe/phishing]
Confidence: [0.0-1.0]
Point of Scam: [Exact entity or "NONE DETECTED"]
Reasoning: [Brief explanation, 1-2 sentences]

Guidelines
Verdict: safe = no scam detected | phishing = scam detected
Confidence: 0.0-1.0 scale
Point of Scam: Exact entity (URL, phone number, app name, account name, service center)
Reasoning: Key factors influencing decision (urgency, sender, entity type, phishing indicators)
"""
        
        response = utils.query_llm(prompt)
        
        if response:
            result = utils.parse_agent_response(response)
            result['urls_found'] = urls_found
            result['sender'] = sender
            
            print(f"[{self.name}] Verdict: {result['verdict']} (confidence: {result['confidence']:.2f})")
            print(f"[{self.name}] Reasoning: {result['reasoning']}")
            
            return result
        else:
            # Fallback if LLM fails
            return {
                'verdict': 'suspicious',
                'confidence': 0.5,
                'reasoning': 'Unable to analyze with LLM, but URLs detected',
                'urls_found': urls_found,
                'sender': sender
            }
