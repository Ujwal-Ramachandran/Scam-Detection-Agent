# SMS Phishing Detection System
A multi-agent phishing detection system powered by DeepSeek R1:7b via Ollama. This system analyzes SMS messages and their embedded links through five specialized detection layers.

## System Architecture
The system uses a sequential verification pipeline with early exit:
1. **SMS Agent** - Analyzes message text and sender
2. **URL Agent** - Examines URL structure and domain
3. **Content Agent** - Analyzes webpage content
4. **Metadata Agent** - Inspects HTTP headers and security
5. **Behavior Agent** - Monitors dynamic page behavior

## Prerequisites
- Python 3.8 or higher
- Ollama installed and running, and a good GPU
- DeepSeek R1:7b model pulled in Ollama
- Chrome/Chromium browser (for Selenium)

## Installation
### Step 1: Install Ollama
Install Ollama for your operating system.

### Step 2: Pull DeepSeek R1:7b Model
```bash
ollama pull deepseek-r1:7b
```

### Step 3: Install Python Dependencies
```bash
pip install -r requirements.txt
```

## Project Structure

```
phishing-detector-agent/
├── config.py           # Configuration settings
├── utils.py            # Utility functions
├── sms_agent.py        # SMS analysis agent
├── url_agent.py        # URL structure analysis agent
├── content_agent.py    # Content analysis agent
├── metadata_agent.py   # Metadata/headers analysis agent
├── behavior_agent.py   # Behavioral analysis agent
├── main.py             # Main orchestration script
├── requirements.txt    # Python dependencies
└── README.md           # This file
```

## Usage

### Running the System

```bash
python main.py
```

### Input Format
The system will prompt you for:
1. **Sender ID/Number**: Enter the SMS sender information
2. **SMS Message**: Enter the full message text

### Example
```
Sender ID/Number: +91-9458756320
Enter SMS message:
URGENT: Your account has been suspended. Click here to verify: http://suspicious-link.com
```

### Output
The system will:
- Analyze the SMS through each detection layer
- Print progress and intermediate results
- Provide a final verdict with confidence score
- Offer recommendations based on the verdict

## Configuration

Edit `config.py` to customize:
- **OLLAMA_MODEL**: Model name (default: "deepseek-r1:7b")
- **CONFIDENCE_THRESHOLD_HIGH**: High confidence threshold (default: 0.8)
- **REQUEST_TIMEOUT**: HTTP request timeout in seconds (default: 10)
- **SELENIUM_TIMEOUT**: Selenium page load timeout (default: 15)

## How Each Agent Works
### 1. SMS Agent
- Extracts URLs from message text
- Analyzes urgency language, grammar, sender info
- **Tools**: Regex, DeepSeek LLM
- **Output**: Safe/Suspicious/Phishing + confidence

### 2. URL Agent
- Parses URL structure and domain features
- Checks for typosquatting, IP addresses, special characters
- **Tools**: tldextract, requests, DeepSeek LLM
- **Output**: Safe/Uncertain/Phishing + confidence

### 3. Content Agent
- Fetches webpage content (without executing JS)
- Analyzes forms, text quality, contact information
- **Tools**: BeautifulSoup, requests, DeepSeek LLM
- **Output**: Safe/Uncertain/Phishing + confidence

### 4. Metadata Agent
- Inspects HTTP response headers
- Checks for security headers (HSTS, CSP, X-Frame-Options)
- **Tools**: requests, DeepSeek LLM
- **Output**: Safe/Uncertain/Phishing + confidence

### 5. Behavior Agent
- Opens page in headless browser
- Monitors redirects, background requests, alerts
- **Tools**: Selenium Wire, Chrome headless, DeepSeek LLM
- **Output**: Safe/Uncertain/Phishing + confidence

## Safety Considerations
⚠️ **WARNING**: The Behavior Agent opens suspicious URLs in a headless browser. While isolated, this carries some risk.

**Recommendations**:
- Run in a virtual machine or Docker container if testing with known malwares or malicious websites
- Never test with personally identifiable credentials
- Comment out behavioral analysis if not needed

## Limitations
- Requires active internet connection
- DeepSeek R1:7b may take 5-10 seconds per analysis
- Behavioral analysis requires Chrome/Chromium
- Some sophisticated phishing sites may evade detection
- False positives possible on legitimate sites with poor security practices

## Future Enhancements
- [ ] Implement parallel agent processing
- [ ] Add confidence score aggregation weights
- [ ] Create web UI interface
- [ ] Add database for caching results
- [ ] Integrate external APIs (VirusTotal, Google Safe Browsing)


## Acknowledgments
- Built with DeepSeek R1:7b via Ollama
- Phishing references from (https://github.com/Phishing-Database/Phishing.Database)
- Selenium Wire for network monitoring

---

**Created by Ujwal Ramachandran for cybersecurity research and education purposes.**
