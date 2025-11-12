import re
import ollama
from urllib.parse import urlparse
from config import OLLAMA_MODEL

def extract_urls_from_text(text):
    """Extract all URLs from text using regex"""
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(url_pattern, text)
    return urls

def query_llm(prompt, system_message="You are a cybersecurity expert specialized in phishing detection."):
    """
    Query via Ollama
    
    Args:
        prompt (str): The user prompt
        system_message (str): System message to set context
    
    Returns:
        str: Model response
    """
    try:
        response = ollama.chat(
            model = OLLAMA_MODEL,
            messages = [
                {"role": "system", "content": system_message},
                {"role": "user", "content": prompt}
            ]
        )
        
        # Remove thinking tags if present
        response_content = response["message"]["content"]
        final_answer = re.sub(r"<think>.*?</think>", "", response_content, flags=re.DOTALL).strip()
        
        return final_answer
    except Exception as e:
        print(f"Error querying LLM: {e}")
        return None

def parse_agent_response(response_text):
    """
    Parse agent response to extract verdict, confidence, and reasoning
    
    Expected format:
    Verdict: safe/phishing/uncertain
    Confidence: 0.0-1.0
    Reasoning: explanation text
    
    Args:
        response_text (str): Raw response from LLM
    
    Returns:
        dict: Parsed response with verdict, confidence, reasoning
    """
    result = {
        "verdict": "uncertain",
        "confidence": 0.0,
        "reasoning": "Failed to parse response"
    }
    
    try:
        lines = response_text.strip().split('\n')
        for line in lines:
            line = line.strip()
            if line.lower().startswith('verdict:'):
                verdict_text = line.split(':', 1)[1].strip().lower()
                if 'safe' in verdict_text:
                    result['verdict'] = 'safe'
                elif 'phishing' in verdict_text:
                    result['verdict'] = 'phishing'
                else:
                    result['verdict'] = 'uncertain'
            
            elif line.lower().startswith('confidence:'):
                conf_text = line.split(':', 1)[1].strip()
                # Extract float from text
                conf_match = re.search(r'\d+\.?\d*', conf_text)
                if conf_match:
                    conf_value = float(conf_match.group())
                    # Normalize to 0-1 range if given as percentage
                    if conf_value > 1.0:
                        conf_value = conf_value / 100.0
                    result['confidence'] = min(max(conf_value, 0.0), 1.0)
            
            elif line.lower().startswith('reasoning:'):
                result['reasoning'] = line.split(':', 1)[1].strip()
        
        # If reasoning wasn't on a separate line, capture everything after "Reasoning:"
        if result['reasoning'] == "Failed to parse response":
            reasoning_match = re.search(r'reasoning:\s*(.+)', response_text, re.IGNORECASE | re.DOTALL)
            if reasoning_match:
                result['reasoning'] = reasoning_match.group(1).strip()
    
    except Exception as e:
        print(f"Error parsing agent response: {e}")
    
    return result

def get_domain_from_url(url):
    """Extract domain from URL"""
    parsed = urlparse(url)
    return parsed.netloc

def is_https(url):
    """Check if URL uses HTTPS"""
    return url.startswith('https://')
