"""
Content Agent - Analyzes website content for phishing indicators
"""

import requests
from bs4 import BeautifulSoup
import utils
import config

class ContentAgent:
    def __init__(self):
        self.name = "ContentAgent"
    
    def analyze(self, data):
        """
        Analyze website content for phishing indicators
        
        Args:
            data (dict): {
                'url': str
            }
        
        Returns:
            dict: {
                'verdict': 'safe'|'phishing'|'uncertain',
                'confidence': float,
                'reasoning': str,
                'content_features': dict
            }
        """
        url = data.get('url', '')
        
        print(f"\n[{self.name}] Analyzing content of: {url}")
        
        # Fetch and analyze content
        content_features = self._extract_content_features(url)
        
        if content_features['error']:
            return {
                'verdict': 'uncertain',
                'confidence': 0.3,
                'reasoning': f"Could not fetch content: {content_features['error']}",
                'content_features': content_features
            }
        
        # Prepare prompt for LLM
        prompt = f"""Analyze this website content for phishing indicators.

URL: {url}
Page Title: {content_features['title']}
Number of Forms: {content_features['form_count']}
Password Fields: {content_features['password_fields']}
Input Fields: {content_features['input_fields']}
External Links: {content_features['external_links']}
Has Contact Info: {content_features['has_contact_info']}
Text Sample: {content_features['text_sample'][:500]}

Check for:
1. Suspicious forms requesting sensitive data
2. Poor grammar and spelling
3. Missing or fake contact information
4. Urgency or threatening language
5. Suspicious external links
6. Low-quality design elements
7. Requests for passwords or financial info

Provide your analysis in this exact format:
Verdict: safe/phishing/uncertain
Confidence: <0.0-1.0>
Reasoning: <brief explanation>
"""
        
        response = utils.query_llm(prompt)
        
        if response:
            result = utils.parse_agent_response(response)
            result['content_features'] = content_features
            
            print(f"[{self.name}] Verdict: {result['verdict']} (confidence: {result['confidence']:.2f})")
            print(f"[{self.name}] Reasoning: {result['reasoning']}")
            
            return result
        else:
            # Fallback analysis
            verdict, confidence = self._fallback_analysis(content_features)
            return {
                'verdict': verdict,
                'confidence': confidence,
                'reasoning': 'Analyzed using heuristics',
                'content_features': content_features
            }
    
    def _extract_content_features(self, url):
        """Fetch and extract features from website content"""
        features = {
            'title': '',
            'form_count': 0,
            'password_fields': 0,
            'input_fields': 0,
            'external_links': 0,
            'has_contact_info': False,
            'text_sample': '',
            'error': None
        }
        
        try:
            headers = {'User-Agent': config.USER_AGENT}
            response = requests.get(url, timeout=config.REQUEST_TIMEOUT, headers=headers)
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract title
            title_tag = soup.find('title')
            features['title'] = title_tag.text.strip() if title_tag else 'No title'
            
            # Count forms and input fields
            forms = soup.find_all('form')
            features['form_count'] = len(forms)
            
            password_inputs = soup.find_all('input', {'type': 'password'})
            features['password_fields'] = len(password_inputs)
            
            all_inputs = soup.find_all('input')
            features['input_fields'] = len(all_inputs)
            
            # Count external links
            links = soup.find_all('a', href=True)
            domain = utils.get_domain_from_url(url)
            external_count = 0
            for link in links:
                href = link['href']
                if href.startswith('http') and domain not in href:
                    external_count += 1
            features['external_links'] = external_count
            
            # Check for contact information
            text_content = soup.get_text().lower()
            contact_keywords = ['contact', 'email', 'phone', 'address', 'support']
            features['has_contact_info'] = any(keyword in text_content for keyword in contact_keywords)
            
            # Get text sample
            features['text_sample'] = soup.get_text()[:1000]
            
        except Exception as e:
            features['error'] = str(e)
        
        return features
    
    def _fallback_analysis(self, features):
        """Simple heuristic-based analysis if LLM fails"""
        suspicious_count = 0
        
        if features['password_fields'] > 0:
            suspicious_count += 2
        if features['form_count'] > 2:
            suspicious_count += 1
        if not features['has_contact_info']:
            suspicious_count += 1
        if features['external_links'] > 10:
            suspicious_count += 1
        
        if suspicious_count >= 3:
            return 'phishing', 0.7
        elif suspicious_count >= 1:
            return 'uncertain', 0.5
        else:
            return 'safe', 0.6
