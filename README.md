# SMS Phishing Detection System 🕵️

A multi-agent AI system that analyzes SMS messages to detect phishing attempts. Built as a fun project to explore how different analysis layers can work together to spot scams!

---

### 🚀 Quick Start

For experienced users, here's how to get up and running in 60 seconds:

```bash
# 1. Clone the repository
git clone <your-repo-url>
cd <your-repo-directory>

# 2. Install dependencies
pip install -r requirements.txt

# 3. Pull and run the LLM
ollama pull deepseek-r1:7b
ollama run deepseek-r1:7b

# 4. Run the detection system
python main.py
```

---

## What Does It Do?

Ever gotten a sketchy SMS with a link asking you to "verify your account" or "claim your prize"? This system analyzes those messages using multiple AI agents that check everything from the message text to the website content, domain info, and security headers. Think of it as having multiple security experts look at the same message from different angles!

## Key Features

The system uses a **multi-agent architecture** where each agent specializes in analyzing different aspects of the SMS:

- **SMS Agent**: Analyzes the message text for urgency, threats, and suspicious patterns
- **URL Agent**: Checks domain age, whois data, URL structure, and JavaScript patterns
- **Content Agent**: Examines webpage content, forms, and password fields
- **Metadata Agent**: Inspects HTTP headers and security configurations
- **Behavior Agent**: **(Disabled by default for performance)** Executes the URL in a sandboxed browser to analyze dynamic behavior, redirects, and network requests.
- **Report Agent**: Generates comprehensive forensic reports with historical pattern analysis

Plus some cool extras:

- **Location Detection**: Identifies host location and phone number country/carrier
- **Progressive Risk Scoring**: Each agent adds risk points with explanations
- **Context Object Pattern**: Agents share findings through a unified context
- **JSON Storage**: Every detection is saved with full audit trail
- **Formatted Reports**: Human-readable reports saved automatically
- **LLM-Powered**: Uses Ollama for intelligent analysis with fallback heuristics

## How It Works

The system follows a pipeline approach where each agent builds on the previous one's findings:

```
📱 SMS Input (Message + Sender)
         ↓
🌍 Get Location Info (Host IP + Phone Number)
         ↓
📝 SMS Agent → Analyzes text, extracts URLs
         ↓
🔗 URL Agent → Checks domain, expands shortened links
         ↓
📄 Content Agent → Analyzes webpage content
         ↓
🔒 Metadata Agent → Checks security headers
         ↓
🕵️ Behavior Agent → (Optional, disabled by default) Analyzes dynamic behavior
         ↓
📊 Aggregate Results → Calculate final verdict
         ↓
💾 Save to JSON + Generate Report
         ↓
✅ Show Results to User
```

Each agent can trigger an **early exit** if it detects high-confidence phishing, making the system fast and efficient.

## Architecture Deep Dive: The Context Object Pattern

The system's architecture is centered around a **Context Object** (`DetectionContext`). This is a powerful design pattern that acts as a centralized, shared memory space for the entire detection pipeline.

-   **How it Works**: Instead of passing dozens of parameters between agents, a single `context` object is passed. Each agent reads the information it needs from the context, performs its analysis, and writes its findings back to the context.
-   **Key Benefits**:
    -   **Decoupling**: Agents don't need to know about each other. They only interact with the shared context. This makes it easy to add, remove, or reorder agents.
    -   **Centralized State**: All information about a detection is in one place, providing a single source of truth.
    -   **Audit Trail**: The context naturally builds a forensic timeline. The `red_flags` and `green_flags` lists record every decision made by every agent, complete with timestamps and reasoning.
    -   **Extensibility**: Adding a new analysis feature is as simple as creating a new agent that reads from and writes to the context. No other agents need to be modified.

This pattern is what allows the system to be both modular and highly transparent.

## Installation

### Prerequisites

You'll need:
- **Python 3.8+**
- **Ollama** (for LLM analysis) - [Install Ollama](https://ollama.ai)
- **Chrome/Chromium** (for Selenium)

### Setup Steps

1. **Clone or download the project**

2. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Install and start Ollama**
   ```bash
   # Install Ollama from https://ollama.ai
   
   # Pull the model (Model used here is deepseek-r1:7b)
   ollama pull deepseek-r1:7b
   
   # Start Ollama server
   ollama run deepseek-r1:7b
   ```

4. **Configure the system** (optional)
   
   Edit `config.py` to customize:
   - LLM model name
   - Confidence thresholds
   - Timeout settings
   - Request parameters

5. **Run the system**
   ```bash
   python main.py
   ```

## Usage

### Basic Usage

Run the main script and follow the prompts:

```bash
python main.py
```

You'll be asked to enter:
1. **Sender ID/Number**: The phone number or sender name
2. **SMS Message**: The message text (press Enter twice when done)

### Example Session

```
Enter SMS details:
Sender ID/Number: +65XXXXXXXX

Enter SMS message (press Enter twice when done):
URGENT: Your account has been suspended. 
Click here to verify: http://bit.ly/abc123


[System] Gathering location information...
[SMSAgent] Analyzing SMS...
[URLAgent] Analyzing URL: http://bit.ly/abc123
[ContentAgent] Analyzing content of: http://example-phishing-site.com
[MetadataAgent] Analyzing metadata of: http://example-phishing-site.com

FINAL VERDICT: PHISHING
Confidence: 0.87
Risk Score: 75/100
```

## Project Structure

```
project/
├── main.py                    # Main orchestration script
├── config.py                  # Configuration settings
├── utils.py                   # Utility functions (LLM, parsing, URL extraction)
│
├── detection_context.py       # DetectionContext class
├── json_storage.py           # JSON file storage handler
├── location_utils.py         # Location detection (geocoder + phonenumbers)
│
├── sms_agent.py              # SMS text analysis agent
├── url_agent.py              # URL structure analysis agent
├── content_agent.py          # Webpage content analysis agent
├── metadata_agent.py         # HTTP headers analysis agent
├── report_agent.py           # Report generation agent
├── behavior_agent.py         # (Disabled by default) Dynamic behavior analysis
│
├── requirements.txt          # Python dependencies
│
│=======  Created after running the code =======
│
├── detections/               # JSON context files (auto-created)
│   ├── 20250115_143022_abc12345.json
│   └── ...
│
├── reports/                  # Formatted report logs (auto-created)
│   ├── phishing_detection_20250115_143022.log
│   └── ...
│
└── phishing_detection.log    # Terminal output log
```

## Output Files

The system generates three types of output files:

### 1. JSON Context Files (`detections/`)

Raw detection data in JSON format:
- Filename: `YYYYMMDD_HHMMSS_{detection_id}.json`
- Contains: Full context with all agent results, risk flags, metadata
- Purpose: Machine-readable, can be loaded for analysis

### 2. Formatted Reports (`reports/`)

Human-readable analysis reports:
- Filename: `phishing_detection_YYYYMMDD_HHMMSS.log`
- Contains: Executive summary, risk analysis, timeline, recommendations
- Purpose: Easy to read and share

### 3. Terminal Logs (`phishing_detection.log`)

Complete console output:
- Filename: `phishing_detection.log`
- Contains: All terminal output, debugging info
- Purpose: Troubleshooting and audit trail

## Configuration

Edit `config.py` to customize the system:

```python

# LLM Configuration
# Change these values as per requirement and convenience
OLLAMA_MODEL = "deepseek-r1:7b"           # Your preferred model

# Confidence Thresholds
CONFIDENCE_THRESHOLD_HIGH = 0.8     # High confidence threshold
CONFIDENCE_THRESHOLD_LOW = 0.3      # Low confidence threshold

# Timeouts
SELENIUM_TIMEOUT = 15               # Selenium page load timeout (seconds)
REQUEST_TIMEOUT = 10                 # HTTP request timeout (seconds)
```

## Risk Scoring System

The system uses a **progressive risk scoring** approach where each agent contributes points based on its findings. The final score is a weighted aggregation of each agent's confidence.

| Agent | Max Points | What It Checks |
| :--- | :--- | :--- |
| SMS Agent | 30 | Urgency, threats, suspicious patterns |
| URL Agent | 35 | Domain age, typosquatting, IP addresses |
| Content Agent | 25 | Forms, password fields, poor quality |
| Metadata Agent | 20 | HTTPS, security headers |
| **Behavior Agent** | 40 | Redirects, network requests, downloads |

**Risk Score Interpretation:**
- **0-30**: Likely safe
- **31-60**: Suspicious, exercise caution
- **61-100+**: High risk, likely phishing

## Real-World Examples

### Example 1: Phishing SMS Detected

**Input:**
```
Sender: OCBC-BANK
Message: Dear customer, your account has been locked due to suspicious activity.
Click here to unlock: http://bit.ly/ocbc-unlock
```

**Output:**
```
VERDICT: PHISHING
Confidence: 0.92
Risk Score: 85/100

Red Flags:
• Urgency language detected
• URL shortener used
• Domain registered 15 days ago
• Password input field detected
• Missing security headers
```

### Example 2: Safe SMS

**Input:**
```
Sender: +65XXXXXXXX
Message: Hey! Are you free for lunch tomorrow? Let me know!
```

**Output:**
```
VERDICT: SAFE
Confidence: 0.95
Risk Score: 0/100

Green Flags:
• No URLs detected in message
• Casual, personal tone
• No urgency or threats
```

### Example 3: Uncertain Verdict

**Input:**
```
Sender: DBS-ALERT
Message: Your OTP for transaction is 123456. Valid for 5 minutes.
```

**Output:**
```
VERDICT: UNCERTAIN
Confidence: 0.50
Risk Score: 25/100

Analysis:
• Legitimate bank format
• No URLs to analyze
• Could be real or spoofed sender
• Recommendation: Verify through official channels
```

## Agents Explained

### SMS Agent

Analyzes the message text for phishing indicators. It looks for urgency language, threats, impersonation attempts, and extracts any URLs found in the message.

**What it checks:**
- Urgency and threatening language
- Brand impersonation
- Grammar and spelling errors
- Suspicious patterns (prizes, account verification, etc.)
- URL extraction

### URL Agent

Examines URL structure and domain information. It expands shortened URLs, checks domain age via whois, and analyzes JavaScript patterns on the page.

**What it checks:**
- URL structure (IP addresses, excessive dots, typosquatting)
- Domain age and registrar information
- URL shorteners (bit.ly, tinyurl, etc.)
- HTTPS usage
- Suspicious JavaScript patterns
- Redirect chains

### Content Agent

Analyzes the actual webpage content by fetching and parsing the HTML. It looks for forms, password fields, and content quality indicators.

**What it checks:**
- Forms and input fields (especially password fields)
- Page title and text content
- Grammar and spelling quality
- Contact information presence
- External links
- Brand impersonation in content

### Metadata Agent

Inspects HTTP headers and security configurations. It checks for proper security headers and HTTPS implementation.

**What it checks:**
- HTTPS usage
- Security headers (HSTS, CSP, X-Frame-Options, etc.)
- Server information
- Status codes and redirects
- Content-Type headers

### Behavior Agent (Disabled by Default)
This is the most powerful agent. It opens the URL in a headless browser to monitor its dynamic behavior.

**What it checks:**
-   Unexpected redirects to different domains
-   Background network requests to suspicious domains
-   Automatic file downloads
-   JavaScript alerts or pop-ups
-   Attempts to collect data without user interaction

### Report Agent

Generates comprehensive forensic reports by analyzing all the collected data. It searches for similar historical patterns and provides actionable recommendations.

**What it generates:**
- Executive summary
- Risk factor breakdown by category
- Historical pattern matching
- Forensic timeline of events
- Confidence explanation
- Actionable recommendations

## Location Detection

The system automatically detects location information to identify mismatches:

### Host Location (using `geocoder`)
- Detects your current IP location
- Returns: Country, city, timezone
- Used to compare with sender location

### Phone Number Analysis (using `phonenumbers`)
- Analyzes sender phone number
- Returns: Country, carrier, number type, validity
- Identifies international vs local numbers

**Location Mismatch Detection:**
If the sender claims to be from a local bank but the phone number is from another country, that's a red flag!

## Troubleshooting

### Ollama Connection Error

**Error:** `Failed to connect to Ollama`

**Solution:**
1. Make sure Ollama is running: `ollama serve`
2. Check if the model is installed: `ollama list`
3. Pull the model if missing: `ollama pull deepseek-r1:7b`
4. Verify the URL in `config.py` matches your Ollama server

### Selenium/ChromeDriver Issues

**Error:** `ChromeDriver not found` or `Selenium timeout`

**Solution:**
1. Install Chrome or Chromium browser
2. Selenium should auto-download ChromeDriver
3. If issues persist, manually install ChromeDriver
4. Increase timeout in `config.py`: `SELENIUM_TIMEOUT = 20`

### Whois Query Timeout

**Error:** `Whois query timed out`

**Solution:**
- Whois queries can be slow (2-10 seconds per URL)
- Some domains block whois queries
- The system will continue with fallback analysis
- Consider adding caching if you analyze the same URLs frequently

### Missing Dependencies

**Error:** `ModuleNotFoundError: No module named 'X'`

**Solution:**
```bash
pip install -r requirements.txt
```

If specific package fails:
```bash
pip install package-name
```

## Limitations

This is a fun project with some limitations to be aware of:

**Performance:**
- Whois queries are slow (2-10 seconds per URL)
- Selenium adds overhead (behavior agent is disabled by default to improve speed)
- Not suitable for real-time high-volume processing

**Accuracy:**
- Depends on LLM quality (fallback heuristics help)
- New phishing techniques may not be detected
- False positives possible on legitimate urgent messages

**Requirements:**
- Needs internet connection
- Requires Ollama running locally
- May visit potentially malicious URLs (be careful!)

**Privacy:**
- Logs contain sensitive data (SMS content, phone numbers)
- JSON files store all detection data
- Secure your output files appropriately

## Security Considerations

**⚠️ Important Safety Notes:**

1. **Visiting Malicious URLs**: The system visits URLs to analyze them. This is done in a controlled Selenium environment, but still carries risk. Consider running in a VM or sandbox.

2. **Data Privacy**: All SMS content, phone numbers, and analysis results are stored in JSON files and logs. Make sure to secure these files and don't share them publicly.

3. **Log File Security**: The `phishing_detection.log` and report files contain sensitive information. Store them securely and consider encrypting them.

4. **False Negatives**: The system is not perfect. Always use your judgment and verify suspicious messages through official channels.

## Performance: With vs. Without Behavior Agent

Enabling the Behavior Agent provides a more thorough analysis at the cost of speed. Here’s a comparison to help you decide whether to enable it.

| Feature | Behavior Agent OFF (Default) | Behavior Agent ON (Advanced) |
| :--- | :--- | :--- |
| **Analysis Time** | **~5-15 seconds** per URL | **~15-30 seconds** per URL |
| **Resource Usage** | Moderate | High (runs a full browser instance) |
| **Detection Capability** | Static analysis (code, headers, domain) | Dynamic analysis (runtime behavior) |
| **Key Detections** | Typosquatting, bad SSL, suspicious forms | **Redirect chains, data exfiltration, drive-by-downloads** |
| **Best For** | Quick, efficient analysis | Maximum accuracy, deep forensic investigation |

**Recommendation:** Keep the Behavior Agent disabled for general use and enable it when you need to perform a deep dive on a particularly suspicious URL.

## About

**Author:** Ujwal Ramachandran

**Affiliation:** Masters Student in Cybersecurity, Nanyang Technological University (NTU), Singapore

This project was built as a fun exploration of multi-agent systems and phishing detection techniques. It combines traditional security analysis with modern LLM capabilities to create a comprehensive detection system.

## Acknowledgments

Built with these awesome libraries:
- **Ollama** - Local LLM inference
- **Selenium** - Web automation
- **BeautifulSoup** - HTML parsing
- **python-whois** - Domain information
- **geocoder** - IP geolocation
- **phonenumbers** - Phone number analysis

---

**Have fun detecting phishing! Stay safe out there! 🛡️**
