# 🔍 ThreatLens – Simple Threat Scanner

ThreatLens is a web-based project I built to scan files and URLs for possible security threats like malware or phishing links.

The goal of this project is to understand how basic threat detection works and how we can analyze suspicious inputs using Python and web technologies.

---

## 🛠️ Tech Used

- Python (Django)
- MongoDB (optional)
- HTML, CSS, JavaScript

---

## 💡 What This Project Does

### 📂 File Scanning
- Checks for known malware patterns
- Detects unusual file content (high entropy)
- Verifies file type vs extension mismatch
- Finds hidden executable content
- Detects macros in documents
- Generates MD5 & SHA-256 hashes

### 🌐 URL Scanning
- Detects suspicious URLs (like IP-based links)
- Identifies phishing keywords
- Checks for fake domains (like paypa1 instead of paypal)
- Detects encoded or manipulated URLs
- Finds possible SQL/XSS injection patterns

---

## ⚙️ Features

- Shows a **risk score (0–100)**
- Classifies threats:
  - CLEAN
  - LOW
  - MEDIUM
  - HIGH
  - CRITICAL
- Stores scan history (if MongoDB is connected)
- Simple UI to test files and URLs

---

## 🚀 How to Run

### Step 1: Install dependencies
```bash
pip install -r requirements.txt