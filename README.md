# Hack Culprit Virtual Internship - Project Report

## Project Title: SecureShare Pro - Encryption File Sharing System with Intrusion Detection

### Submitted by:
- **Name:** Rahul Solanki
- **Internship Role:** Virtual Intern - Cybersecurity Domain
- **Organization:** Hack Culprit
- **GitHub Profile:** https://github.com/rahulsolanki2005
- **Project Duration:** 10/10/2025 – 21/10/2025
- **Project Repository:** https://github.com/rahulsolanki2005/HackCulprit_File-Encryption-System-

---

## 1. Executive Summary

This document outlines the design, development, and implementation of **SecureShare Pro**, an advanced encrypted file-sharing platform with real-time intrusion detection capabilities. Built as part of the Hack Culprit Virtual Internship, this project demonstrates practical cybersecurity implementation using modern cryptographic techniques and security monitoring systems.

The system provides military-grade AES-256 encryption for file storage and transmission, combined with intelligent threat detection mechanisms including brute force protection, suspicious activity monitoring, and comprehensive audit logging. The interactive Streamlit dashboard offers real-time security analytics and user-friendly file management.

---

## 2. Problem Statement

In today's digital landscape, organizations face critical challenges in secure file sharing and storage:

- **Data Breaches:** Sensitive files are vulnerable during transmission and storage
- **Unauthorized Access:** Lack of robust authentication and intrusion detection
- **Compliance Issues:** Need for audit trails and activity monitoring
- **User Experience:** Complex security tools that hinder productivity

**SecureShare Pro** addresses these challenges by providing an intuitive, secure platform that combines enterprise-grade encryption with intelligent security monitoring, making cybersecurity accessible without compromising usability.

---

## 3. Project Objectives

✅ Implement military-grade encryption (AES-256) for file security  
✅ Develop real-time intrusion detection and alert mechanisms  
✅ Create comprehensive activity logging and audit trails  
✅ Build an intuitive dashboard for security analytics  
✅ Apply cybersecurity best practices in authentication and session management  
✅ Gain hands-on experience with Python cryptography libraries  
✅ Utilize version control (Git/GitHub) for professional development workflow  

---

## 4. Development Approach

The project followed a structured four-phase development methodology:

### Phase 1: Requirement Analysis & Planning
- Analyzed security requirements and threat models
- Designed system architecture and data flow
- Selected appropriate cryptographic algorithms and libraries
- Planned dashboard layout and user experience flow

### Phase 2: Core Development
- Implemented PBKDF2-based key derivation (100,000 iterations)
- Developed Fernet symmetric encryption for file operations
- Created SHA-256 hash verification for integrity checks
- Built user authentication with session management
- Integrated brute force detection algorithms

### Phase 3: Security Features Implementation
- Developed intrusion detection system with pattern recognition
- Implemented comprehensive logging infrastructure
- Created real-time alert generation and classification
- Added file integrity verification mechanisms

### Phase 4: UI/UX & Testing
- Designed responsive Streamlit dashboard with custom CSS
- Integrated Plotly for data visualization
- Conducted security testing and penetration testing simulations
- Performed usability testing and UI refinements

---

## 5. Tools & Technologies

| Category | Tools / Technologies Used |
|----------|---------------------------|
| **Programming** | Python 3.12+ |
| **Framework** | Streamlit (Web UI) |
| **Cryptography** | cryptography library (Fernet, PBKDF2HMAC) |
| **Hashing** | hashlib (SHA-256) |
| **Data Analysis** | Pandas, Plotly |
| **Visualization** | Plotly Express, Plotly Graph Objects |
| **Development Tools** | VS Code, Git, GitHub |
| **Security Protocols** | AES-256, PBKDF2, SHA-256 |

---

## 6. Installation & Setup

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- Virtual environment (recommended)

### Step-by-Step Installation

```bash
# Clone the repository
git clone https://github.com/rahulsolanki2005/HackCulprit_File-Encryption-System-

# Navigate to the project directory
cd HackCulprit_File-Encryption-System-

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Linux/Mac:
source venv/bin/activate

# Install required dependencies
pip install streamlit
pip install cryptography
pip install pandas
pip install plotly

# Run the application
streamlit run app.py
```

### Alternative: Using requirements.txt

```bash
# Install all dependencies at once
pip install -r requirements.txt

# Run the application
streamlit run app.py
```

The application will open automatically in your default browser at `http://localhost:8501`

---

## 7. Key Features

### 🔐 Core Security Features
- **AES-256 Encryption:** Military-grade symmetric encryption for all files
- **PBKDF2 Key Derivation:** 100,000 iterations for robust password-based encryption
- **SHA-256 Integrity Check:** Ensures files remain unmodified during storage
- **Secure Authentication:** Hashed password storage with SHA-256
- **Session Management:** Secure user sessions with state management

### 🚨 Intrusion Detection System
- **Brute Force Protection:** Automatically locks accounts after 5 failed login attempts
- **Suspicious Activity Detection:** Monitors and alerts on unusual download patterns
- **Real-time Alert System:** Severity-based alerts (Info, Warning, High, Critical)
- **Pattern Recognition:** Identifies anomalous user behavior

### 📊 Dashboard & Analytics
- **Interactive UI:** Modern, responsive Streamlit interface with custom CSS
- **Real-time Metrics:** Live statistics on files, users, alerts, and activities
- **Data Visualization:** Plotly charts for activity timelines and security events
- **Activity Logs:** Comprehensive audit trail with filtering capabilities
- **Security Alert Center:** Centralized view of all security incidents

### 📁 File Management
- **Encrypted Upload:** Files encrypted before storage with user-defined passwords
- **Secure Download:** Decryption with password verification and integrity checks
- **File Metadata:** Tracks uploader, timestamp, size, and access history
- **Multi-user Support:** User-specific file access and permissions

### 🛡️ Additional Features
- **User Registration:** Secure account creation with password validation
- **Export Functionality:** Download activity logs as CSV for offline analysis
- **Responsive Design:** Clean, professional UI optimized for all screen sizes

---

## 8. Demonstration

### Login & Registration Screen
![Login Screen](<img width="1920" height="987" alt="image" src="https://github.com/user-attachments/assets/317eef97-ee7f-43a0-919d-45d9862211a8" />
)
*Clean, centered authentication interface with gradient design*

### Dashboard Overview
![Dashboard](screenshots/dashboard.png)
*Real-time metrics, charts, and security status at a glance*

### File Management Interface
![File Management](screenshots/file-management.png)
*Intuitive file upload/download with encryption controls*

### Security Alerts Center
![Security Alerts](screenshots/security-alerts.png)
*Color-coded alerts with filtering and severity classification*

### Activity Logs & Analytics
![Activity Logs](screenshots/activity-logs.png)
*Comprehensive audit trail with export functionality*

---

## 9. System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Streamlit Frontend                    │
│  (Dashboard, File Management, Security Alerts, Logs)    │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│              Authentication Layer                        │
│     (Login, Register, Session Management)               │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│           Encryption & Security Module                   │
│   (AES-256, PBKDF2, SHA-256, Integrity Checks)         │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│        Intrusion Detection System (IDS)                  │
│  (Brute Force Detection, Pattern Analysis, Alerts)     │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│              Logging & Audit System                      │
│    (Activity Logs, Security Events, File Metadata)     │
└─────────────────────────────────────────────────────────┘
```

---

## 10. Security Implementation Details

### Encryption Process Flow
1. User uploads file with encryption password
2. PBKDF2 generates encryption key from password (100,000 iterations)
3. Fernet encrypts file data using derived key
4. SHA-256 hash calculated for integrity verification
5. Encrypted data and salt stored in session state
6. Original file data securely discarded

### Intrusion Detection Algorithm
```python
# Brute Force Detection
if failed_login_attempts >= 5 in last_15_minutes:
    trigger_critical_alert()
    lock_account_temporarily()

# Suspicious Activity Pattern
if file_downloads >= 5 in last_10_activities:
    trigger_high_severity_alert()
    log_suspicious_behavior()
```

---

## 11. Challenges Encountered

### Technical Challenges
1. **Cryptography Library Integration**
   - Challenge: Understanding PBKDF2HMAC vs PBKDF2 naming conventions
   - Solution: Thorough documentation review and proper import statements

2. **Password Field Auto-Clear**
   - Challenge: Streamlit's state management limitations
   - Solution: Implemented dynamic key counter mechanism for form reset

3. **Session State Management**
   - Challenge: Maintaining encrypted data in memory without persistence
   - Solution: Leveraged Streamlit's session_state for secure temporary storage

### Security Challenges
1. **Brute Force Detection Accuracy**
   - Challenge: Balancing security with user convenience
   - Solution: Implemented 15-minute sliding window with 5-attempt threshold

2. **File Integrity Verification**
   - Challenge: Ensuring hash verification without performance overhead
   - Solution: SHA-256 pre-computation during encryption phase

---

## 12. Scope for Future Enhancements

### Short-term Enhancements
- [ ] Multi-factor authentication (MFA) support
- [ ] Password strength meter on registration
- [ ] Email notifications for security alerts
- [ ] File sharing between users with access control
- [ ] Encrypted file search functionality

### Long-term Roadmap
- [ ] **Cloud Deployment:** Deploy on AWS/Azure with persistent database
- [ ] **Database Integration:** PostgreSQL/MongoDB for scalable storage
- [ ] **API Development:** RESTful API for third-party integrations
- [ ] **Mobile Application:** React Native mobile client
- [ ] **AI-powered Threat Detection:** Machine learning for anomaly detection
- [ ] **Compliance Reports:** GDPR, HIPAA compliance reporting
- [ ] **File Version Control:** Track and manage file versions
- [ ] **Advanced Analytics:** Predictive threat analysis dashboard

### Technical Improvements
- [ ] Unit testing with pytest (90%+ code coverage)
- [ ] Load testing for concurrent users
- [ ] Docker containerization for easy deployment
- [ ] CI/CD pipeline with GitHub Actions
- [ ] Comprehensive API documentation

---

## 13. Testing & Validation

### Test Scenarios Conducted

| Test Type | Description | Status |
|-----------|-------------|--------|
| **Encryption Test** | Verify AES-256 encryption/decryption | ✅ Passed |
| **Brute Force Test** | 5+ failed logins trigger lock | ✅ Passed |
| **Integrity Check** | SHA-256 hash validation | ✅ Passed |
| **Suspicious Activity** | 5+ downloads trigger alert | ✅ Passed |
| **Password Clear** | Auto-clear after operations | ✅ Passed |
| **Session Management** | Secure login/logout flow | ✅ Passed |
| **UI Responsiveness** | Cross-browser compatibility | ✅ Passed |

---

## 14. Learning Outcomes

### Technical Skills Acquired
- ✅ Advanced Python cryptography implementation
- ✅ Web application development with Streamlit
- ✅ Security best practices and threat modeling
- ✅ Data visualization with Plotly
- ✅ Session state management in web applications
- ✅ Git version control and collaboration

### Cybersecurity Concepts Applied
- ✅ Symmetric encryption (AES-256)
- ✅ Key derivation functions (PBKDF2)
- ✅ Cryptographic hashing (SHA-256)
- ✅ Intrusion detection systems
- ✅ Security event logging and auditing
- ✅ Authentication and authorization

---

## 15. Conclusion

The **SecureShare Pro** project successfully demonstrates the practical application of cybersecurity principles in a real-world file-sharing system. Through this internship project, I gained invaluable hands-on experience in:

- Implementing production-ready encryption systems
- Designing and developing intrusion detection mechanisms
- Building user-friendly security applications
- Following software development best practices

This project not only enhanced my technical capabilities but also deepened my understanding of the critical balance between security and usability. The comprehensive feature set, including real-time threat detection and intuitive dashboard analytics, showcases the potential for secure, enterprise-grade solutions built with modern Python frameworks.

The experience gained through this Hack Culprit internship has significantly contributed to my professional development as a cybersecurity professional, providing a solid foundation for future projects in the security domain.

---

## 16. Acknowledgements

I would like to express my sincere gratitude to the **Hack Culprit** team for providing this valuable learning opportunity. Special thanks to:

- The mentorship team for guidance on cybersecurity best practices
- Fellow interns for collaborative feedback and testing assistance
- The open-source community for excellent cryptography libraries and documentation

This internship has been instrumental in bridging the gap between theoretical knowledge and practical implementation in the cybersecurity field.

---

## 17. Project Structure

```
secureshare-pro/
│
├── app.py                      # Main application file
├── requirements.txt            # Python dependencies
├── README.md                   # Project documentation
│
├── screenshots/                # UI screenshots for documentation
│   ├── login.png
│   ├── dashboard.png
│   ├── file-management.png
│   ├── security-alerts.png
│   └── activity-logs.png
│
└── docs/                       # Additional documentation
    ├── SECURITY.md             # Security policy
    ├── CONTRIBUTING.md         # Contribution guidelines
    └── API.md                  # API documentation (future)
```

---

## 18. License

This project is distributed under the **MIT License**.

```
MIT License

Copyright (c) 2024 [Your Name]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 19. Contact & Support

For questions, suggestions, or collaboration opportunities:

- **GitHub:** [@yourusername](https://github.com/yourusername)
- **Email:** your.email@example.com
- **LinkedIn:** [Your LinkedIn Profile]
- **Project Issues:** [GitHub Issues Page]

---

## 20. Default Credentials (For Testing)

```
Username: admin
Password: admin123
```

⚠️ **Important:** Change default credentials in production environment!

---

**Made with ❤️ during Hack Culprit Virtual Internship**

**#Cybersecurity #Python #Streamlit #Encryption #IntrusionDetection**
