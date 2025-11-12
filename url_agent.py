import requests, re, time
import tldextract
import whois
from urllib.parse import urlparse, parse_qs
import datetime as dt
from utils import parse_agent_response, query_llm
from config import SELENIUM_TIMEOUT, REQUEST_TIMEOUT

class URLAgent:
    def __init__(self):
        """
        URL Agent - Analyzes URL structure and domain information
        """
        self.name = "URLAgent"
    
    def analyze(self, data):
        """
        Analyze URL structure for phishing indicators
        
        Args:
            data (dict): {
                'url': str
            }
        
        Returns:
            dict: {
                'verdict': 'safe'|'phishing'|'uncertain',
                'confidence': float,
                'reasoning': str,
                'url_features': dict,
                'expanded_url': str,
                'was_shortened': bool,
                'javascript_analysis': dict
            }
        """
        url = data.get('url', '')
        
        print(f"\n[{self.name}] Analyzing URL: {url}")
        # Step 1: Expand URL with Selenium
        expanded_url, was_shortened, is_phishing = self.expand_url_with_selenium(url)
        if is_phishing[0]:
            sel_error = str(is_phishing[1])[:15] if len(str(is_phishing[1])) > 15 else str(is_phishing[1])
            return {
                'verdict': 'phishing',
                'confidence': 0.9,
                'reasoning': f'This link was expired and is probably a phishing link. Selenium error: {sel_error}....',
                'url_features': {},
                'expanded_url': expanded_url,
                'was_shortened': was_shortened,
                'javascript_analysis': {}
            }
        # Step 2: Check for malicious JavaScript
        js_analysis = self.check_malicious_javascript(expanded_url)
        
        # Step 3: Extract URL features from expanded URL
        url_features = self._extract_url_features(expanded_url)
        
        # Add expansion info to features
        url_features['original_url'] = url
        url_features['expanded_url'] = expanded_url
        url_features['was_shortened'] = was_shortened
        
        url_display = f"Original URL: {url}\nExpanded URL: {expanded_url}" if was_shortened else f"URL: {url}"
        js_info = ""
        if js_analysis['has_suspicious_js']:
            js_info = f"\nSuspicious JavaScript Detected: {', '.join(js_analysis['suspicious_patterns'])}"
        
        prompt = f"""
        Analyze this URL for phishing indicators: {url_display}
        Domain: {url_features['domain']}
        Subdomain: {url_features['subdomain']}
        Path: {url_features['path']}
        Uses HTTPS: {url_features['is_https']}
        URL Length: {url_features['url_length']}
        Has IP Address: {url_features['has_ip_in_domain']}
        Number of Dots in Domain: {url_features['dot_count']}
        Special Characters: {url_features['special_chars']}
        Was URL Shortened: {was_shortened}
        Domain Age (Days): {url_features['domian_age_days']}
        Registrar URL: {url_features['registrar_url']}
        Name Servers: {url_features['name_servers']}
        DNSSEC: {url_features['dnssec']}
        Registrant Country: {url_features['country']}
        Emails: {url_features['emails']}
        Status: {url_features['status']}

        Check for:
        1. Lack of HTTPS
        2. Typosquatting or misspelled legitimate domains
        3. IP addresses in URLs
        4. Newly registered domains or suspicious registrars (domain age less than 6 months)
        5. Suspicious subdomains
        6. URL shorteners (increases risk as they hide destination)
        7. Suspicious special characters
        8. Malicious JavaScript patterns
        9. Abnormal domain status or DNSSEC configuration
        10. Excessive URL length

        Confidence Weighting: The confidence score should be weighted based on the order of the indicators above. Give higher weight to indicators ranked higher (e.g., typosquatting, suspicious subdomains, IP addresses in URLs) in your confidence calculation.
        When you reason, rememebr this order as well.

        Provide your analysis in this exact format:
        Verdict: safe/phishing
        Confidence: <0.0-1.0>
        Reasoning: <brief explanation>
        If the confidence score is under 0.4 for phishing or safe then return uncertain with reasoning..
        The reasoning should summarize the key factors that influenced your decision. It should not be very big, maximum 1 paragraph. Remember the output should only contain the fields requested(Verdict, Confidence, Reasoning), no additional text.
        """

        response = query_llm(prompt)
        
        if response:
            result = parse_agent_response(response)
            result['url_features'] = url_features
            result['expanded_url'] = expanded_url
            result['was_shortened'] = was_shortened
            result['javascript_analysis'] = js_analysis
            
            print(f"[{self.name}] Verdict: {result['verdict']} (confidence: {result['confidence']:.2f})")
            print(f"[{self.name}] Reasoning: {result['reasoning']}")
            
            return result
        else:
            # Fallback analysis
            verdict, confidence = self._fallback_analysis(url_features, js_analysis)
            return {
                'verdict': verdict,
                'confidence': confidence,
                'reasoning': 'Analyzed using heuristics',
                'url_features': url_features,
                'expanded_url': expanded_url,
                'was_shortened': was_shortened,
                'javascript_analysis': js_analysis
            }
    
    def expand_url_with_selenium(self, url, wait_time=3):
        """
        Open URL with Selenium, wait, and return the final URL
        
        Args:
            url (str): URL to expand
            wait_time (int): Seconds to wait for page load and redirects
        
        Returns:
            tuple: (final_url, was_shortened)
                - final_url (str): Final URL after redirects, or original URL if fails
                - was_shortened (bool): True if URL was redirected/shortened, False otherwise
                - If it was a phishing link or not.
        """
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            from selenium.common.exceptions import TimeoutException, WebDriverException
            print(f"[{self.name}] Opening URL with Selenium...")
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            driver = webdriver.Chrome(options=chrome_options)
            driver.set_page_load_timeout(SELENIUM_TIMEOUT)
            
            try:
                driver.get(url)
                # Wait for potential redirects
                time.sleep(wait_time)
                final_url = driver.current_url
                # Check if URL was shortened/redirected
                was_shortened = (url != final_url)
                if was_shortened:
                    print(f"[{self.name}] URL was shortened: {url} -> {final_url}")
                else:
                    print(f"[{self.name}] URL was not shortened: {final_url}")
                return final_url, was_shortened, [False, ""]
            finally:
                driver.quit()
                
        except ImportError:
            print(f"[{self.name}] Selenium not installed. Install with: pip install selenium")
            return url, False, [False, ""]
        except WebDriverException as e:
            print(f"Selenium WebDriverException occurred: {str(e)}")
            print("This link was expired and is probably a phishing link.")
            return url, False, [True, e]

        except Exception as e:
            print(f"[{self.name}] Error with Selenium: {e}")
            return url, False, [False, ""]
    
    def check_malicious_javascript(self, url):
        """
        Check for malicious or suspicious JavaScript on the webpage
        
        Args:
            url (str): URL to check
        
        Returns:
            dict: {
                'has_suspicious_js': bool,
                'suspicious_patterns': list,
                'js_snippets': list
            }
        """
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            
            print(f"[{self.name}] Checking JavaScript on page...")
            
            # Setup Chrome options
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            
            driver = webdriver.Chrome(options=chrome_options)
            driver.set_page_load_timeout(SELENIUM_TIMEOUT)
            
            try:
                driver.get(url)
                time.sleep(2)
                
                # Get all script tags
                scripts = driver.execute_script("""
                    var scripts = document.getElementsByTagName('script');
                    var scriptContents = [];
                    for (var i = 0; i < scripts.length; i++) {
                        if (scripts[i].src) {
                            scriptContents.push({type: 'external', src: scripts[i].src});
                        } else if (scripts[i].innerHTML) {
                            scriptContents.push({type: 'inline', content: scripts[i].innerHTML});
                        }
                    }
                    return scriptContents;
                """)
                
                # Suspicious patterns to check
                suspicious_patterns = [
                    'eval(',
                    'document.write(',
                    'innerHTML',
                    'onclick',
                    'onerror',
                    'onload',
                    '.cookie',
                    'localStorage',
                    'sessionStorage',
                    'atob(',  # base64 decode
                    'btoa(',  # base64 encode
                    'fromCharCode',
                    'unescape(',
                    'exec(',
                    'addEventListener',
                    'XMLHttpRequest',
                    'fetch(',
                    'redirect',
                    'location.href',
                    'window.location',
                    'document.location'
                ]
                
                found_patterns = []
                suspicious_snippets = []
                
                for script in scripts:
                    if script['type'] == 'inline':
                        content = script['content']
                        
                        # Check for suspicious patterns
                        for pattern in suspicious_patterns:
                            if pattern.lower() in content.lower():
                                if pattern not in found_patterns:
                                    found_patterns.append(pattern)
                                
                                # Extract snippet (50 chars around the pattern)
                                index = content.lower().find(pattern.lower())
                                start = max(0, index - 25)
                                end = min(len(content), index + 25)
                                snippet = content[start:end]
                                suspicious_snippets.append({
                                    'pattern': pattern,
                                    'snippet': snippet.strip()
                                })
                
                result = {
                    'has_suspicious_js': len(found_patterns) > 0,
                    'suspicious_patterns': found_patterns,
                    'js_snippets': suspicious_snippets[:5],
                    'total_scripts': len(scripts),
                    'inline_scripts': sum(1 for s in scripts if s['type'] == 'inline'),
                    'external_scripts': sum(1 for s in scripts if s['type'] == 'external')
                }
                
                print(f"[{self.name}] Found {len(found_patterns)} suspicious JS patterns")
                return result
                
            finally:
                driver.quit()
                
        except ImportError:
            print(f"[{self.name}] Selenium not installed")
            return {
                'has_suspicious_js': False,
                'suspicious_patterns': [],
                'js_snippets': [],
                'error': 'Selenium not available'
            }
        except Exception as e:
            print(f"[{self.name}] Error checking JavaScript: {e}")
            return {
                'has_suspicious_js': False,
                'suspicious_patterns': [],
                'js_snippets': [],
                'error': str(e)
            }
    
    def _extract_url_features(self, url):
        """Extract features from URL"""
        parsed = urlparse(url)
        ext = tldextract.extract(url)
        # Use whois to get domain info
        print(f"Fetching domain info for: url")
        domain_details = whois.whois(url)

        # Check for IP address in domain
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        has_ip = bool(re.search(ip_pattern, parsed.netloc))

        special_chars = sum([url.count(c) for c in ['@', '-', '_']])
        final_url = url
        try:
            response = requests.head(url, allow_redirects=True, timeout=REQUEST_TIMEOUT)
            final_url = response.url
        except:
            pass
        try:
            if isinstance(domain_details.creation_date, list):
                naive_creation_date = domain_details.creation_date[0].replace(tzinfo=None)
            else:
                naive_creation_date = domain_details.creation_date.replace(tzinfo=None)
        except:
            naive_creation_date = domain_details.creation_date
        try:
            domain_age = (dt.datetime.now() - naive_creation_date).days
        except:
            domain_age = (dt.datetime.now() - naive_creation_date)


        features = {
            'domain': ext.domain + '.' + ext.suffix if ext.suffix else ext.domain,
            'subdomain': ext.subdomain,
            'path': parsed.path,
            'query_params': parse_qs(parsed.query),
            'is_https': parsed.scheme == 'https',
            'url_length': len(url),
            'has_ip_in_domain': has_ip,
            'dot_count': parsed.netloc.count('.'),
            'special_chars': special_chars,
            'domian_age_days': domain_age,
            'registrar_url': domain_details.registrar_url,
            'reseller': domain_details.reseller,
            'server': domain_details.whois_server,
            'referral_url': domain_details.referral_url,
            'updated_date': domain_details.updated_date,
            'expiration_date': domain_details.expiration_date,
            'name_servers': domain_details.name_servers,
            'status': domain_details.status,
            'emails': domain_details.emails,
            'dnssec': domain_details.dnssec,
            'name': domain_details.name,
            'org': domain_details.org,
            'address': domain_details.address,
            'city': domain_details.city,
            'state': domain_details.state,
            'registrant_postal_code': domain_details.registrant_postal_code,
            'country': domain_details.country,
            'tech_name': domain_details.tech_name,
            'tech_org': domain_details.tech_org,
            'admin_name': domain_details.admin_name,
            'admin_org': domain_details.admin_org,
            'final_url': final_url
        }
        
        return features
    
    def _fallback_analysis(self, features, js_analysis=None):
        """Simple heuristic-based analysis if LLM fails.
        The more suspicious features, the higher the chance of phishing. There are weights assigned to each feature.
        """
        suspicious_count = 0
        
        if not features['is_https']:
            suspicious_count += 2
        if features['has_ip_in_domain']:
            suspicious_count += 2
        if features['url_length'] > 100:
            suspicious_count += 1
        if features['special_chars'] > 3:
            suspicious_count += 1
        if features.get('was_shortened', False):
            suspicious_count += 1
        
        if js_analysis and js_analysis.get('has_suspicious_js', False):
            suspicious_count += 2
        
        if suspicious_count >= 3:
            return 'phishing', 0.7
        elif suspicious_count >= 1:
            return 'uncertain', 0.4
        else:
            return 'safe', 0.6