"""
Behavior Agent - Analyzes dynamic website behavior using Selenium
"""

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from seleniumwire import webdriver as wire_webdriver
import utils
import config

class BehaviorAgent:
    def __init__(self):
        self.name = "BehaviorAgent"
    
    def analyze(self, data):
        """
        Analyze website behavior for phishing indicators
        
        Args:
            data (dict): {
                'url': str
            }
        
        Returns:
            dict: {
                'verdict': 'safe'|'phishing'|'uncertain',
                'confidence': float,
                'reasoning': str,
                'behavior_features': dict
            }
        """
        url = data.get('url', '')
        
        print(f"\n[{self.name}] Analyzing behavior of: {url}")
        print(f"[{self.name}] WARNING: Opening page in headless browser...")
        
        # Extract behavioral features
        behavior_features = self._extract_behavior_features(url)
        
        if behavior_features['error']:
            return {
                'verdict': 'uncertain',
                'confidence': 0.3,
                'reasoning': f"Could not analyze behavior: {behavior_features['error']}",
                'behavior_features': behavior_features
            }
        
        # Prepare prompt for LLM
        prompt = f"""Analyze this website's behavior for phishing indicators.

URL: {url}
Final URL After Load: {behavior_features['final_url']}
Redirects Detected: {behavior_features['redirect_count']}
Background Requests: {behavior_features['background_request_count']}
Suspicious Domains in Requests: {behavior_features['suspicious_domains']}
JavaScript Alerts: {behavior_features['has_alerts']}
Auto-Downloads: {behavior_features['has_downloads']}

Check for:
1. Unexpected redirects to different domains
2. Multiple background requests to suspicious domains
3. Automatic downloads
4. JavaScript alerts or pop-ups
5. Attempts to collect data without user interaction

Provide your analysis in this exact format:
Verdict: safe/phishing/uncertain
Confidence: <0.0-1.0>
Reasoning: <brief explanation>
"""
        
        response = utils.query_llm(prompt)
        
        if response:
            result = utils.parse_agent_response(response)
            result['behavior_features'] = behavior_features
            
            print(f"[{self.name}] Verdict: {result['verdict']} (confidence: {result['confidence']:.2f})")
            print(f"[{self.name}] Reasoning: {result['reasoning']}")
            
            return result
        else:
            # Fallback analysis
            verdict, confidence = self._fallback_analysis(behavior_features)
            return {
                'verdict': verdict,
                'confidence': confidence,
                'reasoning': 'Analyzed using heuristics',
                'behavior_features': behavior_features
            }
    
    def _extract_behavior_features(self, url):
        """Extract behavioral features using Selenium Wire"""
        features = {
            'final_url': url,
            'redirect_count': 0,
            'background_request_count': 0,
            'suspicious_domains': [],
            'has_alerts': False,
            'has_downloads': False,
            'error': None
        }
        
        driver = None
        
        try:
            # Setup headless Chrome with selenium-wire
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            
            # Use selenium-wire to capture background requests
            driver = wire_webdriver.Chrome(options=chrome_options)
            driver.set_page_load_timeout(config.SELENIUM_TIMEOUT)
            
            # Load page
            driver.get(url)
            
            # Get final URL after redirects
            features['final_url'] = driver.current_url
            
            # Count redirects
            if features['final_url'] != url:
                features['redirect_count'] = 1
            
            # Analyze background requests
            original_domain = utils.get_domain_from_url(url)
            background_domains = set()
            
            for request in driver.requests:
                if request.response:
                    req_domain = utils.get_domain_from_url(request.url)
                    if req_domain != original_domain:
                        background_domains.add(req_domain)
            
            features['background_request_count'] = len(driver.requests)
            features['suspicious_domains'] = list(background_domains)
            
            # Check for alerts (basic check)
            try:
                alert = driver.switch_to.alert
                features['has_alerts'] = True
                alert.dismiss()
            except:
                features['has_alerts'] = False
            
            # Take screenshot for evidence (optional)
            # driver.save_screenshot('phishing_evidence.png')
            
        except Exception as e:
            features['error'] = str(e)
        
        finally:
            if driver:
                driver.quit()
        
        return features
    
    def _fallback_analysis(self, features):
        """Simple heuristic-based analysis if LLM fails"""
        suspicious_count = 0
        
        if features['redirect_count'] > 0:
            suspicious_count += 2
        if len(features['suspicious_domains']) > 5:
            suspicious_count += 1
        if features['has_alerts']:
            suspicious_count += 1
        if features['has_downloads']:
            suspicious_count += 2
        
        if suspicious_count >= 3:
            return 'phishing', 0.8
        elif suspicious_count >= 1:
            return 'uncertain', 0.5
        else:
            return 'safe', 0.6
