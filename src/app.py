from flask import Flask, render_template, request, redirect, url_for, session, flash, g, send_file
try:
    # When running as a package (e.g., gunicorn with src.app:app)
    from .decision_maker import DecisionMaker
except ImportError:  # Fallback for running locally via various working directories
    import os
    import sys
    # Ensure the directory containing this file is on sys.path
    current_dir = os.path.dirname(__file__)
    if current_dir and current_dir not in sys.path:
        sys.path.append(current_dir)
    from decision_maker import DecisionMaker
import numpy as np
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import threading
import random
import string
import time
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import deque

app = Flask(__name__)
decision_maker = DecisionMaker()
app.secret_key = 'your_secret_key_here'  # Set a secret key for session management

# Initialize and train the model with sample data
training_features = np.array([
    [1000, 5000, 2, 30],
    [2000, 3000, 4, 60],
    [500, 1000, 1, 10],
])
historical_decisions = np.array([1, 0, 1])
decision_maker.train(training_features, historical_decisions)

# --- User Authentication Helpers ---
def get_db_connection():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    
    # Check if users table exists and has email column
    cursor = conn.execute("PRAGMA table_info(users)")
    columns = [column[1] for column in cursor.fetchall()]
    
    if 'users' not in [table[0] for table in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]:
        # Create new users table
        conn.execute('''CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_verified BOOLEAN DEFAULT FALSE
        )''')
    elif 'email' not in columns:
        # Add email and is_verified columns to existing table
        try:
            conn.execute('ALTER TABLE users ADD COLUMN email TEXT UNIQUE')
            conn.execute('ALTER TABLE users ADD COLUMN is_verified BOOLEAN DEFAULT FALSE')
        except sqlite3.OperationalError:
            # Column might already exist
            pass
    
    # Create OTP table
    conn.execute('''CREATE TABLE IF NOT EXISTS otp_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        otp TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP DEFAULT (DATETIME('now', '+10 minutes'))
    )''')
    
    conn.commit()
    conn.close()

init_db()

# --- Database Migration Helper ---
def migrate_existing_users():
    """Migrate existing users to have email and verification status"""
    conn = get_db_connection()
    try:
        # Check if email column exists
        cursor = conn.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'email' not in columns:
            # Add email column
            conn.execute('ALTER TABLE users ADD COLUMN email TEXT')
            conn.execute('ALTER TABLE users ADD COLUMN is_verified BOOLEAN DEFAULT FALSE')
            
            # Update existing users to have a default email
            conn.execute('UPDATE users SET email = username || "@example.com", is_verified = TRUE WHERE email IS NULL')
            conn.commit()
            print("Database migrated successfully!")
    except Exception as e:
        print(f"Migration error: {e}")
    finally:
        conn.close()

# Run migration
migrate_existing_users()

# --- OTP Functions ---
def generate_otp():
    """Generate a 6-digit OTP"""
    return ''.join(random.choices(string.digits, k=6))

def send_otp_email(email, otp):
    """Send OTP via email"""
    
    # Email Configuration - UPDATE THESE VALUES
    ENABLE_EMAIL = False  # Set to True to enable email sending
    SENDER_EMAIL = "your-email@gmail.com"  # Your Gmail address
    SENDER_PASSWORD = "your-app-password"  # Your Gmail app password
    
    if ENABLE_EMAIL:
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = SENDER_EMAIL
            msg['To'] = email
            msg['Subject'] = "🔐 Your OTP Verification Code"
            
            # Email body
            body = f"""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f9f9f9;">
                    <div style="background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                        <h2 style="color: #2196f3; text-align: center; margin-bottom: 30px;">🎓 College Admission Advisor</h2>
                        
                        <h3 style="color: #333; margin-bottom: 20px;">Your Verification Code</h3>
                        
                        <div style="background-color: #e3f2fd; padding: 20px; border-radius: 8px; border-left: 4px solid #2196f3; margin-bottom: 20px;">
                            <h1 style="color: #2196f3; text-align: center; font-size: 32px; letter-spacing: 5px; margin: 0;">{otp}</h1>
                        </div>
                        
                        <p style="color: #666; margin-bottom: 15px;">
                            Please enter this 6-digit code to complete your registration for the College Admission Advisor platform.
                        </p>
                        
                        <div style="background-color: #fff3cd; padding: 15px; border-radius: 5px; border-left: 4px solid #ffc107;">
                            <p style="margin: 0; color: #856404; font-size: 14px;">
                                <strong>⚠️ Important:</strong> This code will expire in 10 minutes for security reasons.
                            </p>
                        </div>
                        
                        <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; text-align: center;">
                            <p style="color: #999; font-size: 12px; margin: 0;">
                                If you didn't request this code, please ignore this email.
                            </p>
                        </div>
                    </div>
                </div>
            </body>
            </html>
            """
            
            msg.attach(MIMEText(body, 'html'))
            
            # Send email using Gmail SMTP
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            text = msg.as_string()
            server.sendmail(SENDER_EMAIL, email, text)
            server.quit()
            
            print(f"✅ OTP sent successfully to {email}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to send email: {str(e)}")
            print("Falling back to demo mode...")
    
    # Demo mode (current behavior)
    print("\n" + "="*60)
    print("📧 EMAIL OTP VERIFICATION (DEMO MODE)")
    print("="*60)
    print(f"To: {email}")
    print(f"Subject: 🔐 Your OTP Verification Code")
    print("-"*60)
    print("🎓 College Admission Advisor")
    print("Your Verification Code:")
    print(f"🔢 OTP: {otp}")
    print("-"*60)
    print("Please enter this 6-digit code to complete registration")
    print("⚠️  This code expires in 10 minutes")
    print("="*60 + "\n")
    
    # Store OTP in session for demo purposes
    if 'demo_otp' not in session:
        session['demo_otp'] = {}
    session['demo_otp'][email] = otp
    
    return True

def store_otp(email, otp):
    """Store OTP in database with expiration"""
    conn = get_db_connection()
    # Clear old OTPs for this email
    conn.execute('DELETE FROM otp_codes WHERE email = ?', (email,))
    # Store new OTP
    conn.execute('INSERT INTO otp_codes (email, otp) VALUES (?, ?)', (email, otp))
    conn.commit()
    conn.close()

def check_otp(email, otp):
    """Verify OTP for given email"""
    # Check demo OTP from session first (for testing)
    if 'demo_otp' in session and email in session['demo_otp']:
        if session['demo_otp'][email] == otp:
            # Remove used OTP from session
            session['demo_otp'].pop(email, None)
            return True
    
    # Check database OTP
    conn = get_db_connection()
    result = conn.execute('''
        SELECT * FROM otp_codes 
        WHERE email = ? AND otp = ? AND expires_at > DATETIME('now')
        ORDER BY created_at DESC LIMIT 1
    ''', (email, otp)).fetchone()
    conn.close()
    return result is not None

# --- Registration Route ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        # Check if username or email already exists
        conn = get_db_connection()
        existing_user = conn.execute('SELECT * FROM users WHERE username = ? OR email = ?', (username, email)).fetchone()
        conn.close()
        
        if existing_user:
            if existing_user['username'] == username:
                flash('Username already exists.', 'danger')
            else:
                flash('Email already registered.', 'danger')
            return render_template('register.html')
        
        # Generate and send OTP
        otp = generate_otp()
        if send_otp_email(email, otp):
            store_otp(email, otp)
            session['registration_data'] = {
                'username': username,
                'email': email,
                'password': password
            }
            flash(f'OTP sent to {email}. Please check your email and enter the code below.', 'info')
            return redirect(url_for('verify_otp'))
        else:
            flash('Failed to send OTP. Please try again.', 'danger')
    
    return render_template('register.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'registration_data' not in session:
        flash('Please complete registration first.', 'warning')
        return redirect(url_for('register'))
    
    if request.method == 'POST':
        otp = request.form['otp']
        email = session['registration_data']['email']
        
        if check_otp(email, otp):
            # Registration successful
            username = session['registration_data']['username']
            email = session['registration_data']['email']
            password = session['registration_data']['password']
            hashed_password = generate_password_hash(password)
            
            conn = get_db_connection()
            try:
                conn.execute('INSERT INTO users (username, email, password, is_verified) VALUES (?, ?, ?, ?)', 
                           (username, email, hashed_password, True))
                conn.commit()
                flash('Registration successful! Please log in.', 'success')
                session.pop('registration_data', None)
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Registration failed. Please try again.', 'danger')
            finally:
                conn.close()
        else:
            flash('Invalid or expired OTP. Please try again.', 'danger')
    
    return render_template('verify_otp.html')

@app.route('/resend_otp', methods=['POST'])
def resend_otp():
    if 'registration_data' not in session:
        flash('Please complete registration first.', 'warning')
        return redirect(url_for('register'))
    
    email = session['registration_data']['email']
    otp = generate_otp()
    
    if send_otp_email(email, otp):
        store_otp(email, otp)
        flash('New OTP sent to your email.', 'info')
    else:
        flash('Failed to send OTP. Please try again.', 'danger')
    
    return redirect(url_for('verify_otp'))

# --- Login Route ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password'], password):
            # Handle existing users without email verification
            if 'is_verified' in user.keys() and user['is_verified'] is not None:
                if user['is_verified']:
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    flash('Logged in successfully!', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Please verify your email before logging in.', 'warning')
            else:
                # Existing user without email verification - allow login
                session['user_id'] = user['id']
                session['username'] = user['username']
                flash('Logged in successfully!', 'success')
                return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

# --- Logout Route ---
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# --- Protect Main Page ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=session.get('username'))

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    result = None
    if request.method == 'POST':
        cost = float(request.form['cost'])
        benefit = float(request.form['benefit'])
        risk = float(request.form['risk'])
        time_investment = float(request.form['time_investment'])
        
        new_situation = np.array([cost, benefit, risk, time_investment])
        result = decision_maker.make_decision(new_situation)
        
    return render_template('index.html', result=result)

# --- Admission Route ---
@app.route('/admission', methods=['GET', 'POST'])
@login_required
def admission():
    # EAMCET colleges - Telangana only with realistic rank requirements
    colleges = [
        # Top Tier Colleges (Rank 1-5000)
        {
            'name': 'IIT Hyderabad', 'location': 'Telangana', 
            'streams': {
                'Engineering': {
                    'CSE': {'min_marks': 90, 'min_rank': 300, 'placement': 'Avg Rs.22L, 95% placed'},
                    'ECE': {'min_marks': 88, 'min_rank': 500, 'placement': 'Avg Rs.20L, 92% placed'},
                    'Mechanical': {'min_marks': 85, 'min_rank': 800, 'placement': 'Avg Rs.18L, 90% placed'},
                    'Civil': {'min_marks': 83, 'min_rank': 1000, 'placement': 'Avg Rs.16L, 88% placed'}
                }
            },
            'placement_years': '2023: 92% placed, Avg Rs.19L; 2022: 90% placed, Avg Rs.18L', 
            'avg_package': 'Rs.19L'
        },
        {
            'name': 'NALSAR University of Law', 'location': 'Telangana', 
            'streams': {
                'Arts': {'min_marks': 90, 'min_rank': 800, 'placement': 'Avg Rs.16L, 95% placed'}
            },
            'avg_package': 'Rs.16L'
        },
        {
            'name': 'Indian School of Business (ISB)', 'location': 'Telangana', 
            'streams': {
                'Commerce': {'min_marks': 92, 'min_rank': 200, 'placement': 'Avg Rs.25L, 98% placed'}
            },
            'avg_package': 'Rs.25L'
        },
        {
            'name': 'Gandhi Medical College', 'location': 'Telangana', 
            'streams': {
                'Medical': {'min_marks': 86, 'min_rank': 1200, 'placement': 'Avg Rs.8L, 85% placed'}
            },
            'avg_package': 'Rs.8L'
        },
        {
            'name': 'Apollo Medical College', 'location': 'Telangana', 
            'streams': {
                'Medical': {'min_marks': 85, 'min_rank': 1500, 'placement': 'Avg Rs.9L, 88% placed'}
            },
            'avg_package': 'Rs.9L'
        },
        {
            'name': 'Deccan College of Medical Sciences', 'location': 'Telangana', 
            'streams': {
                'Medical': {'min_marks': 83, 'min_rank': 1800, 'placement': 'Avg Rs.7L, 80% placed'}
            },
            'avg_package': 'Rs.7L'
        },
        {
            'name': 'Shadan Institute of Medical Sciences', 'location': 'Telangana', 
            'streams': {
                'Medical': {'min_marks': 80, 'min_rank': 2000, 'placement': 'Avg Rs.6.5L, 75% placed'}
            },
            'avg_package': 'Rs.6.5L'
        },
        {
            'name': 'Mahindra Ecole Centrale', 'location': 'Telangana', 
            'streams': {
                'Engineering': {'min_marks': 85, 'min_rank': 2500, 'placement': 'Avg Rs.8L, 85% placed'}
            },
            'avg_package': 'Rs.8L'
        },
        {
            'name': 'ICFAI Business School', 'location': 'Telangana', 
            'streams': {
                'Commerce': {'min_marks': 78, 'min_rank': 3000, 'placement': 'Avg Rs.7L, 80% placed'}
            },
            'avg_package': 'Rs.7L'
        },
        {
            'name': 'Institute of Public Enterprise', 'location': 'Telangana', 
            'streams': {
                'Commerce': {'min_marks': 77, 'min_rank': 3500, 'placement': 'Avg Rs.6.5L, 75% placed'}
            },
            'avg_package': 'Rs.6.5L'
        },
        {
            'name': 'Osmania University', 'location': 'Telangana', 
            'streams': {
                'Engineering': {
                    'CSE': {'min_marks': 80, 'min_rank': 4000, 'placement': 'Avg Rs.6L, 80% placed'},
                    'ECE': {'min_marks': 78, 'min_rank': 5000, 'placement': 'Avg Rs.5.5L, 75% placed'},
                    'Mechanical': {'min_marks': 75, 'min_rank': 6000, 'placement': 'Avg Rs.5L, 70% placed'}
                },
                'Arts': {
                    'BA English': {'min_marks': 70, 'min_rank': 8000, 'placement': 'Avg Rs.3L, 60% placed'},
                    'BA History': {'min_marks': 68, 'min_rank': 9000, 'placement': 'Avg Rs.2.8L, 58% placed'}
                },
                'Commerce': {
                    'BCom General': {'min_marks': 72, 'min_rank': 6000, 'placement': 'Avg Rs.4L, 65% placed'},
                    'BCom Computers': {'min_marks': 74, 'min_rank': 5500, 'placement': 'Avg Rs.4.2L, 68% placed'}
                },
                'Science': {
                    'BSc Physics': {'min_marks': 73, 'min_rank': 5000, 'placement': 'Avg Rs.4.5L, 68% placed'},
                    'BSc Chemistry': {'min_marks': 72, 'min_rank': 5200, 'placement': 'Avg Rs.4.3L, 67% placed'}
                }
            },
            'avg_package': 'Rs.5L'
        },
        {
            'name': 'JNTU Hyderabad', 'location': 'Telangana', 
            'streams': {
                'Engineering': {'min_marks': 82, 'min_rank': 4000, 'placement': 'Avg Rs.7L, 80% placed'}
            },
            'placement_years': '2023: 75% placed, Avg Rs.6L; 2022: 72% placed, Avg Rs.5.5L', 
            'avg_package': 'Rs.6L'
        },
        
        # Mid Tier Colleges (Rank 5000-15000)
        {
            'name': 'Nizam College', 'location': 'Telangana', 
            'streams': {
                'Arts': {'min_marks': 68, 'min_rank': 8000, 'placement': 'Avg Rs.3L, 55% placed'},
                'Commerce': {'min_marks': 70, 'min_rank': 6000, 'placement': 'Avg Rs.4L, 65% placed'},
                'Science': {'min_marks': 71, 'min_rank': 5500, 'placement': 'Avg Rs.4.5L, 68% placed'}
            },
            'avg_package': 'Rs.4L'
        },
        {
            'name': 'University College of Engineering (OU)', 'location': 'Telangana', 
            'streams': {
                'Engineering': {'min_marks': 79, 'min_rank': 6000, 'placement': 'Avg Rs.6L, 78% placed'}
            },
            'avg_package': 'Rs.6L'
        },
        {
            'name': 'Vasavi College of Engineering', 'location': 'Telangana', 
            'streams': {
                'Engineering': {'min_marks': 80, 'min_rank': 7000, 'placement': 'Avg Rs.6.5L, 80% placed'}
            },
            'avg_package': 'Rs.6.5L'
        },
        {
            'name': 'BV Raju Institute of Technology', 'location': 'Telangana', 
            'streams': {
                'Engineering': {'min_marks': 78, 'min_rank': 7500, 'placement': 'Avg Rs.6L, 78% placed'}
            },
            'avg_package': 'Rs.6L'
        },
        {
            'name': 'CBIT', 'location': 'Telangana', 
            'streams': {
                'Engineering': {'min_marks': 84, 'min_rank': 6000, 'placement': 'Avg Rs.8L, 88% placed'}
            },
            'placement_years': '2023: 85% placed, Avg Rs.7L; 2022: 80% placed, Avg Rs.6.5L', 
            'avg_package': 'Rs.7L'
        },
        {
            'name': 'Malla Reddy College of Engineering', 'location': 'Telangana', 
            'streams': {
                'Engineering': {'min_marks': 75, 'min_rank': 9000, 'placement': 'Avg Rs.5.5L, 75% placed'}
            },
            'avg_package': 'Rs.5.5L'
        },
        {
            'name': 'St. Francis College for Women', 'location': 'Telangana', 
            'streams': {
                'Arts': {'min_marks': 70, 'min_rank': 5500, 'placement': 'Avg Rs.3.5L, 60% placed'},
                'Commerce': {'min_marks': 72, 'min_rank': 4500, 'placement': 'Avg Rs.4L, 65% placed'},
                'Science': {'min_marks': 73, 'min_rank': 4000, 'placement': 'Avg Rs.4.5L, 70% placed'}
            },
            'avg_package': 'Rs.3.5L'
        },
        {
            'name': "St. Ann's College for Women", 'location': 'Telangana', 
            'streams': {
                'Arts': {'min_marks': 68, 'min_rank': 6500, 'placement': 'Avg Rs.3L, 60% placed'},
                'Commerce': {'min_marks': 70, 'min_rank': 5500, 'placement': 'Avg Rs.3.5L, 65% placed'},
                'Science': {'min_marks': 71, 'min_rank': 5000, 'placement': 'Avg Rs.4L, 68% placed'}
            },
            'avg_package': 'Rs.3L'
        },
        {
            'name': "Aurora's Degree & PG College", 'location': 'Telangana', 
            'streams': {
                'Arts': {'min_marks': 65, 'min_rank': 8000, 'placement': 'Avg Rs.2.5L, 55% placed'},
                'Commerce': {'min_marks': 68, 'min_rank': 7000, 'placement': 'Avg Rs.3L, 60% placed'},
                'Science': {'min_marks': 69, 'min_rank': 6500, 'placement': 'Avg Rs.3.5L, 62% placed'}
            },
            'avg_package': 'Rs.2.5L'
        },
        {
            'name': 'VNR Vignana Jyothi Institute of Engineering & Technology', 'location': 'Telangana', 
            'streams': {
                'Engineering': {'min_marks': 80, 'min_rank': 10000, 'placement': 'Avg Rs.6.5L, 85% placed'}
            },
            'placement_years': '2023: 80% placed, Avg Rs.5.5L; 2022: 78% placed, Avg Rs.5L', 
            'avg_package': 'Rs.5.5L'
        },
        {
            'name': 'Gokaraju Rangaraju Institute of Engineering & Technology', 'location': 'Telangana', 
            'streams': {
                'Engineering': {'min_marks': 79, 'min_rank': 12000, 'placement': 'Avg Rs.6L, 82% placed'}
            },
            'placement_years': '2023: 78% placed, Avg Rs.5.2L; 2022: 75% placed, Avg Rs.4.8L', 
            'avg_package': 'Rs.5.2L'
        },
        
        # Lower Tier Colleges (Rank 15000+)
        {
            'name': 'CMR College of Engineering & Technology', 'location': 'Telangana', 
            'streams': {
                'Engineering': {'min_marks': 77, 'min_rank': 15000, 'placement': 'Avg Rs.5.5L, 80% placed'}
            },
            'placement_years': '2023: 75% placed, Avg Rs.4.8L; 2022: 72% placed, Avg Rs.4.5L', 
            'avg_package': 'Rs.4.8L'
        },
        {
            'name': 'Mahatma Gandhi Institute of Technology (MGIT)', 'location': 'Telangana', 
            'streams': {
                'Engineering': {'min_marks': 78, 'min_rank': 17000, 'placement': 'Avg Rs.5.8L, 80% placed'}
            },
            'placement_years': '2023: 76% placed, Avg Rs.5L; 2022: 74% placed, Avg Rs.4.7L', 
            'avg_package': 'Rs.5L'
        },
        {
            'name': 'Institute of Aeronautical Engineering (IARE)', 'location': 'Telangana', 
            'streams': {
                'Engineering': {'min_marks': 76, 'min_rank': 22000, 'placement': 'Avg Rs.5.2L, 78% placed'}
            },
            'placement_years': '2023: 73% placed, Avg Rs.4.6L; 2022: 70% placed, Avg Rs.4.2L', 
            'avg_package': 'Rs.4.6L'
        },
    ]
    result = None
    if request.method == 'POST':
        marks = float(request.form['marks'])
        degree = request.form['degree']
        stream = request.form['stream']
        sub_course = request.form.get('sub_course', '')  # Get sub-course if provided
        caste = request.form['caste']
        sex = request.form['sex']
        # Predict EAMCET rank based on marks and caste (realistic formula)
        # EAMCET total marks: 160, Total candidates: ~2.5 lakhs
        # Rank distribution is exponential - higher marks = exponentially better rank
        
        if caste == 'OC':
            # OC category - most competitive
            if marks >= 140:
                predicted_rank = int(100 + (160 - marks) * 30)  # Top 1000 for 140+ marks
            elif marks >= 120:
                predicted_rank = int(1000 + (140 - marks) * 150)  # 1000-5000 for 120-140 marks
            elif marks >= 100:
                predicted_rank = int(5000 + (120 - marks) * 300)  # 5000-15000 for 100-120 marks
            elif marks >= 80:
                predicted_rank = int(15000 + (100 - marks) * 800)  # 15000-35000 for 80-100 marks
            else:
                predicted_rank = int(35000 + (80 - marks) * 1500)  # 35000+ for <80 marks
                
        elif caste == 'BC':
            # BC category - 25% reservation
            if marks >= 130:
                predicted_rank = int(200 + (160 - marks) * 80)
            elif marks >= 110:
                predicted_rank = int(2000 + (130 - marks) * 200)
            elif marks >= 90:
                predicted_rank = int(8000 + (110 - marks) * 400)
            elif marks >= 70:
                predicted_rank = int(20000 + (90 - marks) * 800)
            else:
                predicted_rank = int(40000 + (70 - marks) * 1500)
                
        elif caste == 'SC':
            # SC category - 15% reservation
            if marks >= 120:
                predicted_rank = int(500 + (160 - marks) * 100)
            elif marks >= 100:
                predicted_rank = int(3000 + (120 - marks) * 250)
            elif marks >= 80:
                predicted_rank = int(10000 + (100 - marks) * 500)
            elif marks >= 60:
                predicted_rank = int(25000 + (80 - marks) * 1000)
            else:
                predicted_rank = int(50000 + (60 - marks) * 2000)
                
        elif caste == 'ST':
            # ST category - 6% reservation
            if marks >= 110:
                predicted_rank = int(1000 + (160 - marks) * 150)
            elif marks >= 90:
                predicted_rank = int(5000 + (110 - marks) * 300)
            elif marks >= 70:
                predicted_rank = int(15000 + (90 - marks) * 600)
            elif marks >= 50:
                predicted_rank = int(30000 + (70 - marks) * 1000)
            else:
                predicted_rank = int(60000 + (50 - marks) * 2000)
                
        elif caste == 'EWS':
            # EWS category - 10% reservation
            if marks >= 135:
                predicted_rank = int(300 + (160 - marks) * 100)
            elif marks >= 115:
                predicted_rank = int(3000 + (135 - marks) * 200)
            elif marks >= 95:
                predicted_rank = int(8000 + (115 - marks) * 400)
            elif marks >= 75:
                predicted_rank = int(20000 + (95 - marks) * 800)
            else:
                predicted_rank = int(40000 + (75 - marks) * 1500)
                
        else:
            # Other category
            if marks >= 125:
                predicted_rank = int(500 + (160 - marks) * 80)
            elif marks >= 105:
                predicted_rank = int(3000 + (125 - marks) * 200)
            elif marks >= 85:
                predicted_rank = int(10000 + (105 - marks) * 400)
            elif marks >= 65:
                predicted_rank = int(25000 + (85 - marks) * 800)
            else:
                predicted_rank = int(50000 + (65 - marks) * 1500)
        # Filter colleges by stream and create accurate ranking based on marks and rank
        suggested = []
        for c in colleges:
            # Women's colleges logic
            womens_colleges = ["St. Francis College for Women", "St. Ann's College for Women"]
            if sex == 'Female':
                # Female students can see all colleges
                pass
            else:
                # Male/Other: skip women's colleges
                if c['name'] in womens_colleges:
                    continue
            if stream in c['streams']:
                # Get stream-specific requirements
                stream_data = c['streams'][stream]
                
                # Handle sub-courses if specified
                if sub_course and isinstance(stream_data, dict) and sub_course in stream_data:
                    # Use specific sub-course requirements
                    course_data = stream_data[sub_course]
                    min_marks = course_data['min_marks']
                    min_rank = course_data['min_rank']
                    placement = course_data['placement']
                elif isinstance(stream_data, dict) and any(isinstance(v, dict) for v in stream_data.values()):
                    # Stream has sub-courses but no specific sub-course selected
                    # Use the first available sub-course or general stream data
                    if sub_course and sub_course in stream_data:
                        course_data = stream_data[sub_course]
                        min_marks = course_data['min_marks']
                        min_rank = course_data['min_rank']
                        placement = course_data['placement']
                    else:
                        # Use first available sub-course or general requirements
                        first_sub_course = next(iter(stream_data.values()))
                        if isinstance(first_sub_course, dict):
                            min_marks = first_sub_course['min_marks']
                            min_rank = first_sub_course['min_rank']
                            placement = first_sub_course['placement']
                        else:
                            # Fallback to general stream data
                            min_marks = stream_data['min_marks']
                            min_rank = stream_data['min_rank']
                            placement = stream_data['placement']
                else:
                    # Stream has no sub-courses, use general stream data
                    min_marks = stream_data['min_marks']
                    min_rank = stream_data['min_rank']
                    placement = stream_data['placement']
                
                # Check if student qualifies for this college based on caste
                qualifies = False
                rank_score = 0
                marks_score = 0
                
                # Caste-based qualification logic
                if caste == 'OC':
                    # OC - most competitive, no reservation benefit
                    rank_required = min_rank
                    marks_required = min_marks
                elif caste == 'BC':
                    # BC - 25% reservation, slight relaxation
                    rank_required = min_rank * 1.2  # 20% relaxation
                    marks_required = min_marks - 2  # 2 marks relaxation
                elif caste == 'SC':
                    # SC - 15% reservation, significant relaxation
                    rank_required = min_rank * 1.5  # 50% relaxation
                    marks_required = min_marks - 5  # 5 marks relaxation
                elif caste == 'ST':
                    # ST - 6% reservation, maximum relaxation
                    rank_required = min_rank * 2.0  # 100% relaxation
                    marks_required = min_marks - 8  # 8 marks relaxation
                elif caste == 'EWS':
                    # EWS - 10% reservation, moderate relaxation
                    rank_required = min_rank * 1.3  # 30% relaxation
                    marks_required = min_marks - 3  # 3 marks relaxation
                else:
                    # Other category
                    rank_required = min_rank * 1.1  # 10% relaxation
                    marks_required = min_marks - 1  # 1 mark relaxation
                
                # Check rank-based qualification with caste benefit
                rank_qualifies = False
                if predicted_rank <= rank_required:
                    rank_qualifies = True
                    # Better rank = higher score (closer to college rank = better)
                    rank_score = 1000 - (rank_required - predicted_rank)
                
                # Check marks-based qualification with caste benefit
                marks_qualifies = False
                if marks >= marks_required:
                    marks_qualifies = True
                    # Better marks = higher score
                    marks_score = 500 - (marks_required - marks)
                
                # Student qualifies only if they meet BOTH rank AND marks requirements
                qualifies = rank_qualifies and marks_qualifies
                
                # Always add college to suggestions, but with different scoring for qualified vs non-qualified
                if qualifies:
                    # Student qualifies - give full score
                    score = max(rank_score, marks_score)  # Use the better of rank or marks score
                    qualification_status = "Qualified"
                else:
                    # Student doesn't qualify - give partial score based on how close they are
                    score = 0
                    # Calculate how close they are to qualifying by rank
                    rank_diff = rank_required - predicted_rank
                    if rank_diff > 0:
                        # More realistic scoring - closer rank = higher score, but with diminishing returns
                        score = max(0, 200 - rank_diff * 0.05)  # Closer = higher score
                    
                    # Calculate how close they are to qualifying by marks
                    marks_diff = marks_required - marks
                    if marks_diff > 0:
                        marks_score = max(0, 100 - marks_diff * 5)  # Closer = higher score
                        score = max(score, marks_score)
                    
                    qualification_status = "Not Qualified"
                
                # Add package bonus (higher package = higher score)
                placement_text = placement
                package_bonus = 0
                if 'Rs.' in placement_text:
                    try:
                        package_start = placement_text.find('Rs.') + 3
                        package_end = placement_text.find('L', package_start)
                        if package_end != -1:
                            avg_package = float(placement_text[package_start:package_end])
                            package_bonus = avg_package * 5  # Higher package = higher score
                    except:
                        pass
                
                # Add placement percentage bonus
                placement_bonus = 0
                if '%' in placement_text:
                    try:
                        # Extract placement percentage
                        percent_part = placement_text.split(',')[1].strip()
                        percent_start = percent_part.find('%')
                        if percent_start != -1:
                            placement_percent = float(percent_part[:percent_start])
                            placement_bonus = placement_percent * 2
                    except:
                        pass
                
                # Add reputation bonus
                reputation_bonus = 0
                if 'IIT' in c['name']:
                    reputation_bonus = 300
                elif 'ISB' in c['name'] or 'NALSAR' in c['name']:
                    reputation_bonus = 250
                elif 'University' in c['name']:
                    reputation_bonus = 100
                elif 'Institute' in c['name']:
                    reputation_bonus = 50
                
                # Calculate final score
                final_score = score + package_bonus + placement_bonus + reputation_bonus
                
                # Add college to suggestions with detailed scoring info
                c['score'] = final_score
                c['rank_score'] = rank_score
                c['marks_score'] = marks_score
                c['package_bonus'] = package_bonus
                c['placement_bonus'] = placement_bonus
                c['reputation_bonus'] = reputation_bonus
                c['qualifies_by_rank'] = predicted_rank <= rank_required
                c['qualifies_by_marks'] = marks >= marks_required
                c['qualification_status'] = qualification_status
                
                # Calculate chance of admission with caste consideration
                admission_chance = 0
                if qualifies:
                    # Student meets both rank and marks requirements
                    rank_advantage = rank_required - predicted_rank
                    marks_advantage = marks - marks_required
                    
                    # Calculate overall advantage
                    if rank_advantage >= 2000 and marks_advantage >= 10:
                        admission_chance = 95  # Very high chance
                    elif rank_advantage >= 1000 and marks_advantage >= 5:
                        admission_chance = 85  # High chance
                    elif rank_advantage >= 500 and marks_advantage >= 2:
                        admission_chance = 75  # Good chance
                    elif rank_advantage >= 200 and marks_advantage >= 0:
                        admission_chance = 65  # Moderate chance
                    else:
                        admission_chance = 55  # Low chance
                else:
                    # Student doesn't meet both requirements
                    if not rank_qualifies and not marks_qualifies:
                        # Doesn't meet either requirement
                        admission_chance = 5   # Very difficult
                    elif not rank_qualifies:
                        # Meets marks but not rank
                        rank_gap = rank_required - predicted_rank
                        if rank_gap <= 2000:
                            admission_chance = 30  # Some chance with improvement
                        elif rank_gap <= 5000:
                            admission_chance = 20  # Difficult but possible
                        else:
                            admission_chance = 10  # Very difficult
                    else:
                        # Meets rank but not marks
                        marks_gap = marks_required - marks
                        if marks_gap <= 5:
                            admission_chance = 25  # Some chance
                        elif marks_gap <= 10:
                            admission_chance = 15  # Difficult
                        else:
                            admission_chance = 5   # Very difficult
                
                c['admission_chance'] = admission_chance
                c['min_marks'] = min_marks
                suggested.append(c)
        
        # Sort by admission chance (highest first)
        suggested.sort(key=lambda c: c['admission_chance'], reverse=True)
        
        # Limit to top 15 colleges for better variety
        suggested = suggested[:15]
        # Show rank as a realistic range (±10% of predicted rank)
        rank_variance = max(100, int(predicted_rank * 0.1))  # At least 100, or 10% of rank
        rank_low = max(1, predicted_rank - rank_variance)
        rank_high = predicted_rank + rank_variance
        predicted_rank_range = f"{rank_low:,} - {rank_high:,}"
        result = {'predicted_rank': predicted_rank, 'predicted_rank_range': predicted_rank_range, 'stream': stream, 'degree': degree, 'caste': caste, 'colleges': suggested}
        # Pass form data back to preserve values
        form_data = {'marks': marks, 'degree': degree, 'stream': stream, 'sub_course': sub_course, 'caste': caste, 'sex': sex}
    else:
        form_data = {}
    return render_template('admission.html', result=result, form_data=form_data)

@app.route('/colleges')
@login_required
def colleges():
    # EAMCET colleges - Telangana only with realistic rank requirements
    colleges = [
        # Top Tier Colleges (Rank 1-5000)
        {
            'name': 'IIT Hyderabad', 'location': 'Telangana', 
            'streams': {
                'Engineering': {
                    'CSE': {'min_marks': 90, 'min_rank': 300, 'placement': 'Avg Rs.22L, 95% placed'},
                    'ECE': {'min_marks': 88, 'min_rank': 500, 'placement': 'Avg Rs.20L, 92% placed'},
                    'Mechanical': {'min_marks': 85, 'min_rank': 800, 'placement': 'Avg Rs.18L, 90% placed'},
                    'Civil': {'min_marks': 83, 'min_rank': 1000, 'placement': 'Avg Rs.16L, 88% placed'}
                }
            },
            'placement_years': '2023: 92% placed, Avg Rs.19L; 2022: 90% placed, Avg Rs.18L', 
            'avg_package': 'Rs.19L'
        },
        {
            'name': 'NALSAR University of Law', 'location': 'Telangana', 
            'streams': {
                'Arts': {'min_marks': 90, 'min_rank': 800, 'placement': 'Avg Rs.16L, 95% placed'}
            },
            'avg_package': 'Rs.16L'
        },
        {
            'name': 'Indian School of Business (ISB)', 'location': 'Telangana', 
            'streams': {
                'Commerce': {'min_marks': 92, 'min_rank': 200, 'placement': 'Avg Rs.25L, 98% placed'}
            },
            'avg_package': 'Rs.25L'
        },
        {
            'name': 'Gandhi Medical College', 'location': 'Telangana', 
            'streams': {
                'Medical': {'min_marks': 86, 'min_rank': 1200, 'placement': 'Avg Rs.8L, 85% placed'}
            },
            'avg_package': 'Rs.8L'
        },
        {
            'name': 'Apollo Medical College', 'location': 'Telangana', 
            'streams': {
                'Medical': {'min_marks': 85, 'min_rank': 1500, 'placement': 'Avg Rs.9L, 88% placed'}
            },
            'avg_package': 'Rs.9L'
        },
        {
            'name': 'Deccan College of Medical Sciences', 'location': 'Telangana', 
            'streams': {
                'Medical': {'min_marks': 83, 'min_rank': 1800, 'placement': 'Avg Rs.7L, 80% placed'}
            },
            'avg_package': 'Rs.7L'
        },
        {
            'name': 'Shadan Institute of Medical Sciences', 'location': 'Telangana', 
            'streams': {
                'Medical': {'min_marks': 80, 'min_rank': 2000, 'placement': 'Avg Rs.6.5L, 75% placed'}
            },
            'avg_package': 'Rs.6.5L'
        },
        {
            'name': 'Mahindra Ecole Centrale', 'location': 'Telangana', 
            'streams': {
                'Engineering': {'min_marks': 85, 'min_rank': 2500, 'placement': 'Avg Rs.8L, 85% placed'}
            },
            'avg_package': 'Rs.8L'
        },
        {
            'name': 'ICFAI Business School', 'location': 'Telangana', 
            'streams': {
                'Commerce': {'min_marks': 78, 'min_rank': 3000, 'placement': 'Avg Rs.7L, 80% placed'}
            },
            'avg_package': 'Rs.7L'
        },
        {
            'name': 'Institute of Public Enterprise', 'location': 'Telangana', 
            'streams': {
                'Commerce': {'min_marks': 77, 'min_rank': 3500, 'placement': 'Avg Rs.6.5L, 75% placed'}
            },
            'avg_package': 'Rs.6.5L'
        },
        {
            'name': 'Osmania University', 'location': 'Telangana', 
            'streams': {
                'Engineering': {
                    'CSE': {'min_marks': 80, 'min_rank': 4000, 'placement': 'Avg Rs.6L, 80% placed'},
                    'ECE': {'min_marks': 78, 'min_rank': 5000, 'placement': 'Avg Rs.5.5L, 75% placed'},
                    'Mechanical': {'min_marks': 75, 'min_rank': 6000, 'placement': 'Avg Rs.5L, 70% placed'}
                },
                'Arts': {
                    'BA English': {'min_marks': 70, 'min_rank': 8000, 'placement': 'Avg Rs.3L, 60% placed'},
                    'BA History': {'min_marks': 68, 'min_rank': 9000, 'placement': 'Avg Rs.2.8L, 58% placed'}
                },
                'Commerce': {
                    'BCom General': {'min_marks': 72, 'min_rank': 6000, 'placement': 'Avg Rs.4L, 65% placed'},
                    'BCom Computers': {'min_marks': 74, 'min_rank': 5500, 'placement': 'Avg Rs.4.2L, 68% placed'}
                },
                'Science': {
                    'BSc Physics': {'min_marks': 73, 'min_rank': 5000, 'placement': 'Avg Rs.4.5L, 68% placed'},
                    'BSc Chemistry': {'min_marks': 72, 'min_rank': 5200, 'placement': 'Avg Rs.4.3L, 67% placed'}
                }
            },
            'avg_package': 'Rs.5L'
        },
        {
            'name': 'JNTU Hyderabad', 'location': 'Telangana', 
            'streams': {
                'Engineering': {'min_marks': 82, 'min_rank': 4000, 'placement': 'Avg Rs.7L, 80% placed'}
            },
            'placement_years': '2023: 75% placed, Avg Rs.6L; 2022: 72% placed, Avg Rs.5.5L', 
            'avg_package': 'Rs.6L'
        },
        
        # Mid Tier Colleges (Rank 5000-15000)
        {
            'name': 'Nizam College', 'location': 'Telangana', 
            'streams': {
                'Arts': {'min_marks': 68, 'min_rank': 8000, 'placement': 'Avg Rs.3L, 55% placed'},
                'Commerce': {'min_marks': 70, 'min_rank': 6000, 'placement': 'Avg Rs.4L, 65% placed'},
                'Science': {'min_marks': 71, 'min_rank': 5500, 'placement': 'Avg Rs.4.5L, 68% placed'}
            },
            'avg_package': 'Rs.4L'
        },
        {
            'name': 'University College of Engineering (OU)', 'location': 'Telangana', 
            'streams': {
                'Engineering': {'min_marks': 79, 'min_rank': 6000, 'placement': 'Avg Rs.6L, 78% placed'}
            },
            'avg_package': 'Rs.6L'
        },
        {
            'name': 'Vasavi College of Engineering', 'location': 'Telangana', 
            'streams': {
                'Engineering': {'min_marks': 80, 'min_rank': 7000, 'placement': 'Avg Rs.6.5L, 80% placed'}
            },
            'avg_package': 'Rs.6.5L'
        },
        {
            'name': 'BV Raju Institute of Technology', 'location': 'Telangana', 
            'streams': {
                'Engineering': {'min_marks': 78, 'min_rank': 7500, 'placement': 'Avg Rs.6L, 78% placed'}
            },
            'avg_package': 'Rs.6L'
        },
        {
            'name': 'CBIT', 'location': 'Telangana', 
            'streams': {
                'Engineering': {'min_marks': 84, 'min_rank': 6000, 'placement': 'Avg Rs.8L, 88% placed'}
            },
            'placement_years': '2023: 85% placed, Avg Rs.7L; 2022: 80% placed, Avg Rs.6.5L', 
            'avg_package': 'Rs.7L'
        },
        {
            'name': 'Malla Reddy College of Engineering', 'location': 'Telangana', 
            'streams': {
                'Engineering': {'min_marks': 75, 'min_rank': 9000, 'placement': 'Avg Rs.5.5L, 75% placed'}
            },
            'avg_package': 'Rs.5.5L'
        },
        {
            'name': 'St. Francis College for Women', 'location': 'Telangana', 
            'streams': {
                'Arts': {'min_marks': 70, 'min_rank': 5500, 'placement': 'Avg Rs.3.5L, 60% placed'},
                'Commerce': {'min_marks': 72, 'min_rank': 4500, 'placement': 'Avg Rs.4L, 65% placed'},
                'Science': {'min_marks': 73, 'min_rank': 4000, 'placement': 'Avg Rs.4.5L, 70% placed'}
            },
            'avg_package': 'Rs.3.5L'
        },
        {
            'name': "St. Ann's College for Women", 'location': 'Telangana', 
            'streams': {
                'Arts': {'min_marks': 68, 'min_rank': 6500, 'placement': 'Avg Rs.3L, 60% placed'},
                'Commerce': {'min_marks': 70, 'min_rank': 5500, 'placement': 'Avg Rs.3.5L, 65% placed'},
                'Science': {'min_marks': 71, 'min_rank': 5000, 'placement': 'Avg Rs.4L, 68% placed'}
            },
            'avg_package': 'Rs.3L'
        },
        {
            'name': "Aurora's Degree & PG College", 'location': 'Telangana', 
            'streams': {
                'Arts': {'min_marks': 65, 'min_rank': 8000, 'placement': 'Avg Rs.2.5L, 55% placed'},
                'Commerce': {'min_marks': 68, 'min_rank': 7000, 'placement': 'Avg Rs.3L, 60% placed'},
                'Science': {'min_marks': 69, 'min_rank': 6500, 'placement': 'Avg Rs.3.5L, 62% placed'}
            },
            'avg_package': 'Rs.2.5L'
        },
        {
            'name': 'VNR Vignana Jyothi Institute of Engineering & Technology', 'location': 'Telangana', 
            'streams': {
                'Engineering': {'min_marks': 80, 'min_rank': 10000, 'placement': 'Avg Rs.6.5L, 85% placed'}
            },
            'placement_years': '2023: 80% placed, Avg Rs.5.5L; 2022: 78% placed, Avg Rs.5L', 
            'avg_package': 'Rs.5.5L'
        },
        {
            'name': 'Gokaraju Rangaraju Institute of Engineering & Technology', 'location': 'Telangana', 
            'streams': {
                'Engineering': {'min_marks': 79, 'min_rank': 12000, 'placement': 'Avg Rs.6L, 82% placed'}
            },
            'placement_years': '2023: 78% placed, Avg Rs.5.2L; 2022: 75% placed, Avg Rs.4.8L', 
            'avg_package': 'Rs.5.2L'
        },
        
        # Lower Tier Colleges (Rank 15000+)
        {
            'name': 'CMR College of Engineering & Technology', 'location': 'Telangana', 
            'streams': {
                'Engineering': {'min_marks': 77, 'min_rank': 15000, 'placement': 'Avg Rs.5.5L, 80% placed'}
            },
            'placement_years': '2023: 75% placed, Avg Rs.4.8L; 2022: 72% placed, Avg Rs.4.5L', 
            'avg_package': 'Rs.4.8L'
        },
        {
            'name': 'Mahatma Gandhi Institute of Technology (MGIT)', 'location': 'Telangana', 
            'streams': {
                'Engineering': {'min_marks': 78, 'min_rank': 17000, 'placement': 'Avg Rs.5.8L, 80% placed'}
            },
            'placement_years': '2023: 76% placed, Avg Rs.5L; 2022: 74% placed, Avg Rs.4.7L', 
            'avg_package': 'Rs.5L'
        },
        {
            'name': 'Institute of Aeronautical Engineering (IARE)', 'location': 'Telangana', 
            'streams': {
                'Engineering': {'min_marks': 76, 'min_rank': 22000, 'placement': 'Avg Rs.5.2L, 78% placed'}
            },
            'placement_years': '2023: 73% placed, Avg Rs.4.6L; 2022: 70% placed, Avg Rs.4.2L', 
            'avg_package': 'Rs.4.6L'
        },
    ]
    
    # Organize colleges by tier based on minimum rank across all streams
    def get_min_rank(college):
        min_rank = float('inf')
        for stream_name, stream_data in college['streams'].items():
            # Handle nested sub-course structure
            if isinstance(stream_data, dict) and any(isinstance(v, dict) for v in stream_data.values()):
                # Stream has sub-courses, find the minimum rank across all sub-courses
                for sub_course_data in stream_data.values():
                    if isinstance(sub_course_data, dict) and 'min_rank' in sub_course_data:
                        min_rank = min(min_rank, sub_course_data['min_rank'])
            else:
                # Simple stream data structure
                if isinstance(stream_data, dict) and 'min_rank' in stream_data:
                    min_rank = min(min_rank, stream_data['min_rank'])
        return min_rank if min_rank != float('inf') else 99999  # Default if no valid rank found
    
    top_tier = [c for c in colleges if get_min_rank(c) <= 5000]
    mid_tier = [c for c in colleges if 5000 < get_min_rank(c) <= 15000]
    lower_tier = [c for c in colleges if get_min_rank(c) > 15000]
    
    return render_template('colleges.html', 
                         top_tier=top_tier, 
                         mid_tier=mid_tier, 
                         lower_tier=lower_tier,
                         total_colleges=len(colleges))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)