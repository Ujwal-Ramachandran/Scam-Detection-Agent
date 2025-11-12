"""
Metadata Agent - Analyzes HTTP headers and metadata
"""

import requests
import utils
import config
from detection_context import DetectionContext

class MetadataAgent:
    def __init__(self):
        self.name = "MetadataAgent"
    
    def analyze(self, context: DetectionContext, url: str) -> DetectionContext:
        """
        Analyze HTTP headers and metadata for phishing indicators
        
        Args:
            context: DetectionContext with current analysis state
            url: URL to analyze metadata from
        
        Returns:
            Updated DetectionContext with metadata analysis results
        """
        
        print(f"\n[{self.name}] Analyzing metadata of: {url}")
        
        # Extract metadata features
        metadata_features = self._extract_metadata_features(url)
        
        if metadata_features['error']:
            result = {
                'verdict': 'uncertain',
                'confidence': 0.3,
                'reasoning': f"Could not fetch metadata: {metadata_features['error']}",
                'metadata_features': metadata_features
            }
            context.set_agent_result(self.name, result)
            return context
        
        # Prepare prompt for LLM
        prompt = f"""Analyze this website's HTTP headers and metadata for phishing indicators.

URL: {url}
Status Code: {metadata_features['status_code']}
Server: {metadata_features['server']}
Content-Type: {metadata_features['content_type']}
Has HTTPS: {metadata_features['is_https']}
Has Security Headers:
  - Strict-Transport-Security: {metadata_features['has_hsts']}
  - Content-Security-Policy: {metadata_features['has_csp']}
  - X-Frame-Options: {metadata_features['has_xfo']}
  - X-Content-Type-Options: {metadata_features['has_xcto']}

Check for:
1. Missing security headers
2. Suspicious server information
3. Unusual status codes or redirects
4. Lack of HTTPS
5. Unusual content types

Provide your analysis in this exact format:
Verdict: safe/phishing
Confidence: <0.0-1.0>
Reasoning: <brief explanation>
If the confidence score is under 0.4 for phishing or safe then return uncertain with reasoning.
The reasoning should summarize the key factors that influenced your decision. It should not be very big, maximum 1 paragraph. Remember the output should only contain the fields requested(Verdict, Confidence, Reasoning), no additional text.
"""
        
        response = utils.query_llm(prompt)
        
        if response:
            result = utils.parse_agent_response(response)
            result['metadata_features'] = metadata_features
            
            print(f"[{self.name}] Verdict: {result['verdict']} (confidence: {result['confidence']:.2f})")
            print(f"[{self.name}] Reasoning: {result['reasoning']}")
            
        else:
            # Fallback analysis
            verdict, confidence = self._fallback_analysis(metadata_features)
            result = {
                'verdict': verdict,
                'confidence': confidence,
                'reasoning': 'Analyzed using heuristics',
                'metadata_features': metadata_features
            }
        
        # Update context
        context.set_agent_result(self.name, result)
        
        # Calculate security headers score
        security_score = sum([
            metadata_features.get('has_hsts', False),
            metadata_features.get('has_csp', False),
            metadata_features.get('has_xfo', False),
            metadata_features.get('has_xcto', False)
        ]) * 25  # 0-100 scale
        context.security_headers_score = security_score
        
        # Add risk/green flags
        if result['verdict'] == 'phishing':
            risk_points = int(result['confidence'] * 20)  # Max 20 points from metadata
            context.add_risk(risk_points, result['reasoning'], self.name)
        elif result['verdict'] == 'safe':
            context.add_green_flag(result['reasoning'], self.name)
        
        # Add specific risk flags
        if not metadata_features.get('is_https', False):
            context.add_risk(15, 'No HTTPS encryption', self.name)
        
        if security_score < 50:
            context.add_risk(10, f'Poor security headers (score: {security_score}/100)', self.name)
        elif security_score >= 75:
            context.add_green_flag(f'Good security headers (score: {security_score}/100)', self.name)
        
        return context
    
    def _extract_metadata_features(self, url):
        """Fetch and extract metadata features"""
        features = {
            'status_code': 0,
            'server': 'Unknown',
            'content_type': 'Unknown',
            'is_https': False,
            'has_hsts': False,
            'has_csp': False,
            'has_xfo': False,
            'has_xcto': False,
            'all_headers': {},
            'error': None
        }
        
        try:
            headers = {'User-Agent': config.USER_AGENT}
            response = requests.get(url, timeout=config.REQUEST_TIMEOUT, headers=headers)
            
            features['status_code'] = response.status_code
            features['server'] = response.headers.get('Server', 'Unknown')
            features['content_type'] = response.headers.get('Content-Type', 'Unknown')
            features['is_https'] = url.startswith('https')
            
            # Check security headers
            features['has_hsts'] = 'Strict-Transport-Security' in response.headers
            features['has_csp'] = 'Content-Security-Policy' in response.headers
            features['has_xfo'] = 'X-Frame-Options' in response.headers
            features['has_xcto'] = 'X-Content-Type-Options' in response.headers
            
            features['all_headers'] = dict(response.headers)
            
        except Exception as e:
            features['error'] = str(e)
        
        return features
    
    def _fallback_analysis(self, features):
        """Simple heuristic-based analysis if LLM fails"""
        suspicious_count = 0
        
        if not features['is_https']:
            suspicious_count += 2
        
        # Missing security headers
        security_headers = [
            features['has_hsts'],
            features['has_csp'],
            features['has_xfo'],
            features['has_xcto']
        ]
        missing_headers = sum(1 for h in security_headers if not h)
        
        if missing_headers >= 3:
            suspicious_count += 1
        
        if features['status_code'] not in [200, 301, 302]:
            suspicious_count += 1
        
        if suspicious_count >= 3:
            return 'phishing', 0.7
        elif suspicious_count >= 1:
            return 'uncertain', 0.5
        else:
            return 'safe', 0.6
