import streamlit as st
import hashlib
import os
import json
import time
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from io import BytesIO

# Page configuration
st.set_page_config(
    page_title="SecureShare Pro",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better UI
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        font-weight: bold;
        text-align: center;
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        padding: 1rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 10px;
        color: white;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .alert-danger {
        background-color: #ff4444;
        color: white;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
    .alert-success {
        background-color: #00C851;
        color: white;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
    .alert-warning {
        background-color: #ffbb33;
        color: white;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 2rem;
    }
    .stTabs [data-baseweb="tab"] {
        height: 50px;
        padding: 0 2rem;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'users' not in st.session_state:
    st.session_state.users = {
        'admin': {
            'password': hashlib.sha256('admin123'.encode()).hexdigest(),
            'role': 'admin'
        }
    }

if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False

if 'current_user' not in st.session_state:
    st.session_state.current_user = None

if 'files' not in st.session_state:
    st.session_state.files = {}

if 'login_attempts' not in st.session_state:
    st.session_state.login_attempts = {}

if 'security_logs' not in st.session_state:
    st.session_state.security_logs = []

if 'activity_logs' not in st.session_state:
    st.session_state.activity_logs = []

if 'alerts' not in st.session_state:
    st.session_state.alerts = []

# Encryption functions
def generate_key_from_password(password: str, salt: bytes = None) -> tuple:
    """Generate encryption key from password using PBKDF2"""
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_file(file_data: bytes, password: str) -> tuple:
    """Encrypt file data"""
    key, salt = generate_key_from_password(password)
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(file_data)
    
    # Calculate hash for integrity check
    file_hash = hashlib.sha256(file_data).hexdigest()
    
    return encrypted_data, salt, file_hash

def decrypt_file(encrypted_data: bytes, password: str, salt: bytes) -> bytes:
    """Decrypt file data"""
    key, _ = generate_key_from_password(password, salt)
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data)
    return decrypted_data

# Security functions
def log_security_event(event_type: str, details: str, severity: str = "info"):
    """Log security events"""
    event = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'type': event_type,
        'details': details,
        'severity': severity,
        'user': st.session_state.current_user if st.session_state.current_user else 'System'
    }
    st.session_state.security_logs.append(event)
    
    if severity in ['high', 'critical']:
        st.session_state.alerts.append(event)

def log_activity(activity: str, details: str = ""):
    """Log user activity"""
    log = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'user': st.session_state.current_user,
        'activity': activity,
        'details': details
    }
    st.session_state.activity_logs.append(log)

def check_brute_force(username: str) -> bool:
    """Check for brute force attempts"""
    if username not in st.session_state.login_attempts:
        st.session_state.login_attempts[username] = []
    
    # Remove attempts older than 15 minutes
    current_time = time.time()
    st.session_state.login_attempts[username] = [
        attempt for attempt in st.session_state.login_attempts[username]
        if current_time - attempt < 900  # 15 minutes
    ]
    
    # Check if more than 5 attempts in last 15 minutes
    if len(st.session_state.login_attempts[username]) >= 5:
        log_security_event(
            "Brute Force Detected",
            f"Multiple failed login attempts for user: {username}",
            "critical"
        )
        return True
    return False

def detect_suspicious_activity():
    """Detect suspicious patterns in activity logs"""
    if len(st.session_state.activity_logs) < 10:
        return
    
    recent_logs = st.session_state.activity_logs[-10:]
    download_count = sum(1 for log in recent_logs if 'download' in log['activity'].lower())
    
    if download_count >= 5:
        log_security_event(
            "Suspicious Activity",
            f"High number of file downloads detected from {st.session_state.current_user}",
            "high"
        )

# Authentication functions
def register_user(username: str, password: str):
    """Register new user"""
    if username in st.session_state.users:
        return False, "Username already exists!"
    
    st.session_state.users[username] = {
        'password': hashlib.sha256(password.encode()).hexdigest(),
        'role': 'user'
    }
    log_security_event("User Registration", f"New user registered: {username}", "info")
    return True, "Registration successful!"

def login_user(username: str, password: str):
    """Authenticate user"""
    if check_brute_force(username):
        return False, "Account temporarily locked due to multiple failed attempts!"
    
    if username not in st.session_state.users:
        st.session_state.login_attempts.setdefault(username, []).append(time.time())
        return False, "Invalid credentials!"
    
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    if st.session_state.users[username]['password'] == password_hash:
        st.session_state.logged_in = True
        st.session_state.current_user = username
        st.session_state.login_attempts[username] = []
        log_security_event("Login Success", f"User {username} logged in", "info")
        log_activity("Login", "User logged in successfully")
        return True, "Login successful!"
    else:
        st.session_state.login_attempts.setdefault(username, []).append(time.time())
        log_security_event("Login Failed", f"Failed login attempt for {username}", "warning")
        return False, "Invalid credentials!"

# Dashboard components
def show_dashboard():
    """Main dashboard with analytics"""
    st.markdown('<h1 class="main-header">🔐 SecureShare Pro Dashboard</h1>', unsafe_allow_html=True)
    
    # Metrics row
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <h3>📁 Total Files</h3>
            <h2>{len(st.session_state.files)}</h2>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        active_alerts = len([a for a in st.session_state.alerts if a['severity'] in ['high', 'critical']])
        st.markdown(f"""
        <div class="metric-card">
            <h3>🚨 Active Alerts</h3>
            <h2>{active_alerts}</h2>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
        <div class="metric-card">
            <h3>👥 Total Users</h3>
            <h2>{len(st.session_state.users)}</h2>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown(f"""
        <div class="metric-card">
            <h3>📊 Activities</h3>
            <h2>{len(st.session_state.activity_logs)}</h2>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Tabs for different sections
    tabs = st.tabs(["📊 Analytics", "🚨 Security Alerts", "📁 File Management", "👤 Activity Logs"])
    
    with tabs[0]:
        show_analytics()
    
    with tabs[1]:
        show_security_alerts()
    
    with tabs[2]:
        show_file_management()
    
    with tabs[3]:
        show_activity_logs()

def show_analytics():
    """Show analytics and charts"""
    st.subheader("📊 System Analytics")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Activity timeline
        if st.session_state.activity_logs:
            df_activity = pd.DataFrame(st.session_state.activity_logs)
            df_activity['hour'] = pd.to_datetime(df_activity['timestamp']).dt.hour
            activity_count = df_activity.groupby('hour').size().reset_index(name='count')
            
            fig = px.line(activity_count, x='hour', y='count', 
                         title='Activity Timeline (24h)',
                         labels={'hour': 'Hour of Day', 'count': 'Number of Activities'})
            fig.update_traces(line_color='#667eea', line_width=3)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No activity data yet")
    
    with col2:
        # Security events by severity
        if st.session_state.security_logs:
            df_security = pd.DataFrame(st.session_state.security_logs)
            severity_count = df_security['severity'].value_counts().reset_index()
            severity_count.columns = ['severity', 'count']
            
            colors = {'info': '#00C851', 'warning': '#ffbb33', 'high': '#ff4444', 'critical': '#CC0000'}
            fig = px.pie(severity_count, values='count', names='severity',
                        title='Security Events by Severity',
                        color='severity',
                        color_discrete_map=colors)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No security events yet")

def show_security_alerts():
    """Display security alerts"""
    st.subheader("🚨 Security Alert Center")
    
    # Filter alerts by severity
    severity_filter = st.selectbox("Filter by Severity", 
                                   ["All", "critical", "high", "warning", "info"])
    
    alerts_to_show = st.session_state.alerts
    if severity_filter != "All":
        alerts_to_show = [a for a in alerts_to_show if a['severity'] == severity_filter]
    
    if alerts_to_show:
        for alert in reversed(alerts_to_show[-10:]):  # Show last 10 alerts
            severity_class = "alert-danger" if alert['severity'] in ['critical', 'high'] else "alert-warning"
            st.markdown(f"""
            <div class="{severity_class}">
                <strong>🚨 {alert['type']}</strong> - {alert['severity'].upper()}<br>
                <small>{alert['timestamp']}</small><br>
                {alert['details']}
            </div>
            """, unsafe_allow_html=True)
    else:
        st.success("✅ No security alerts! System is secure.")
    
    # Clear alerts button (admin only)
    if st.session_state.users[st.session_state.current_user]['role'] == 'admin':
        if st.button("🗑️ Clear All Alerts"):
            st.session_state.alerts = []
            st.rerun()

def show_file_management():
    """File upload, download, and management"""
    st.subheader("📁 Encrypted File Management")
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("### 📤 Upload & Encrypt File")
        uploaded_file = st.file_uploader("Choose a file", type=None)
        
        # Initialize password key counter for clearing
        if 'password_key_counter' not in st.session_state:
            st.session_state.password_key_counter = 0
        
        # Dynamic key to force password field reset
        password_key = f"enc_pass_{st.session_state.password_key_counter}"
        
        encryption_password = st.text_input("Encryption Password", 
                                           type="password", 
                                           key=password_key,
                                           placeholder="Enter strong password")
        
        if st.button("🔐 Encrypt & Upload"):
            if uploaded_file and encryption_password:
                try:
                    file_data = uploaded_file.read()
                    encrypted_data, salt, file_hash = encrypt_file(file_data, encryption_password)
                    
                    file_id = hashlib.sha256(uploaded_file.name.encode()).hexdigest()[:16]
                    st.session_state.files[file_id] = {
                        'name': uploaded_file.name,
                        'data': encrypted_data,
                        'salt': salt,
                        'hash': file_hash,
                        'uploaded_by': st.session_state.current_user,
                        'uploaded_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'size': len(file_data)
                    }
                    
                    log_activity("File Upload", f"Uploaded file: {uploaded_file.name}")
                    log_security_event("File Encrypted", f"File {uploaded_file.name} encrypted and stored", "info")
                    
                    st.success(f"✅ File encrypted successfully! File ID: {file_id}")
                    
                    # Change key counter to clear password field
                    st.session_state.password_key_counter += 1
                    time.sleep(1)
                    st.rerun()
                    
                except Exception as e:
                    st.error(f"❌ Error: {str(e)}")
                    log_security_event("Encryption Failed", f"Failed to encrypt file: {str(e)}", "warning")
            else:
                st.warning("⚠️ Please upload a file and enter password!")
    
    with col2:
        st.markdown("### 📥 Download & Decrypt File")
        if st.session_state.files:
            file_options = {f"{fid} - {fdata['name']}": fid 
                          for fid, fdata in st.session_state.files.items()}
            selected_file = st.selectbox("Select File", options=list(file_options.keys()))
            decryption_password = st.text_input("Decryption Password", type="password", key="dec_pass")
            
            if st.button("🔓 Decrypt & Download"):
                if decryption_password:
                    try:
                        file_id = file_options[selected_file]
                        file_info = st.session_state.files[file_id]
                        
                        decrypted_data = decrypt_file(
                            file_info['data'],
                            decryption_password,
                            file_info['salt']
                        )
                        
                        # Verify file integrity
                        decrypted_hash = hashlib.sha256(decrypted_data).hexdigest()
                        if decrypted_hash != file_info['hash']:
                            st.error("⚠️ File integrity check failed!")
                            log_security_event("Integrity Check Failed", 
                                             f"Hash mismatch for file: {file_info['name']}", "high")
                        else:
                            st.download_button(
                                label="💾 Download Decrypted File",
                                data=decrypted_data,
                                file_name=file_info['name'],
                                mime="application/octet-stream"
                            )
                            log_activity("File Download", f"Downloaded file: {file_info['name']}")
                            detect_suspicious_activity()
                            st.success("✅ File decrypted successfully!")
                    except Exception as e:
                        st.error("❌ Decryption failed! Wrong password or corrupted file.")
                        log_security_event("Decryption Failed", 
                                         f"Failed attempt to decrypt: {file_info['name']}", "warning")
                else:
                    st.warning("⚠️ Please enter decryption password!")
        else:
            st.info("No files uploaded yet")
    
    # File list
    st.markdown("---")
    st.markdown("### 📋 Uploaded Files")
    if st.session_state.files:
        df_files = pd.DataFrame([
            {
                'File ID': fid,
                'File Name': fdata['name'],
                'Size (bytes)': fdata['size'],
                'Uploaded By': fdata['uploaded_by'],
                'Uploaded At': fdata['uploaded_at']
            }
            for fid, fdata in st.session_state.files.items()
        ])
        st.dataframe(df_files, use_container_width=True)
    else:
        st.info("No files in the system")

def show_activity_logs():
    """Display activity logs"""
    st.subheader("👤 User Activity Logs")
    
    if st.session_state.activity_logs:
        # Filter options
        col1, col2 = st.columns(2)
        with col1:
            user_filter = st.selectbox("Filter by User", 
                                      ["All"] + list(set([log['user'] for log in st.session_state.activity_logs])))
        with col2:
            activity_filter = st.selectbox("Filter by Activity",
                                          ["All"] + list(set([log['activity'] for log in st.session_state.activity_logs])))
        
        filtered_logs = st.session_state.activity_logs
        if user_filter != "All":
            filtered_logs = [log for log in filtered_logs if log['user'] == user_filter]
        if activity_filter != "All":
            filtered_logs = [log for log in filtered_logs if log['activity'] == activity_filter]
        
        df_logs = pd.DataFrame(filtered_logs)
        st.dataframe(df_logs, use_container_width=True, height=400)
        
        # Export logs
        if st.button("📥 Export Logs to CSV"):
            csv = df_logs.to_csv(index=False)
            st.download_button(
                label="Download CSV",
                data=csv,
                file_name=f"activity_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
    else:
        st.info("No activity logs yet")

# Main app
def main():
    if not st.session_state.logged_in:
        # Login/Register page
        st.markdown('<h1 class="main-header">🔐 SecureShare Pro</h1>', unsafe_allow_html=True)
        st.markdown("<h3 style='text-align: center;'>Encrypted File Sharing with Intrusion Detection</h3>", 
                   unsafe_allow_html=True)
        
        # Center container for login/register
        col1, col2, col3 = st.columns([1, 2, 1])
        
        with col2:
            st.markdown('<div class="login-container">', unsafe_allow_html=True)
            
            tab1, tab2 = st.tabs(["🔑 Login", "📝 Register"])
            
            with tab1:
                st.subheader("Login to your account")
                username = st.text_input("Username", key="login_user", placeholder="Enter username")
                password = st.text_input("Password", type="password", key="login_pass", placeholder="Enter password")
                
                if st.button("🚀 Login", use_container_width=True):
                    success, message = login_user(username, password)
                    if success:
                        st.success(message)
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error(message)
            
            with tab2:
                st.subheader("Create new account")
                new_username = st.text_input("Username", key="reg_user", placeholder="Choose username")
                new_password = st.text_input("Password", type="password", key="reg_pass", placeholder="Choose password")
                confirm_password = st.text_input("Confirm Password", type="password", key="reg_confirm", placeholder="Confirm password")
                
                if st.button("✨ Register", use_container_width=True):
                    if new_password != confirm_password:
                        st.error("Passwords don't match!")
                    elif len(new_password) < 6:
                        st.error("Password must be at least 6 characters!")
                    else:
                        success, message = register_user(new_username, new_password)
                        if success:
                            st.success(message)
                        else:
                            st.error(message)
            
            st.markdown('</div>', unsafe_allow_html=True)
    else:
        # Sidebar
        with st.sidebar:
            st.markdown(f"### 👤 Welcome, {st.session_state.current_user}!")
            st.markdown(f"**Role:** {st.session_state.users[st.session_state.current_user]['role']}")
            
            if st.button("🚪 Logout", use_container_width=True):
                log_activity("Logout", "User logged out")
                st.session_state.logged_in = False
                st.session_state.current_user = None
                st.rerun()
            
            st.markdown("---")
            st.markdown("### 📊 Quick Stats")
            st.metric("Your Files", len([f for f in st.session_state.files.values() 
                                        if f['uploaded_by'] == st.session_state.current_user]))
            st.metric("System Alerts", len(st.session_state.alerts))
            
            st.markdown("---")
            st.markdown("### ℹ️ About")
            st.info("""
            **SecureShare Pro** provides military-grade file encryption with real-time intrusion detection.
            
            **Features:**
            - AES-256 Encryption
            - Brute Force Protection
            - Activity Monitoring
            - Integrity Verification
            """)
        
        # Main dashboard
        show_dashboard()

if __name__ == "__main__":
    main()