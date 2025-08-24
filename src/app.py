from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, session
import json
import sqlite3
import random
import string
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from werkzeug.security import generate_password_hash, check_password_hash
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

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Required for sessions and flash messages
decision_maker = DecisionMaker()
# No secret key needed since authentication is removed

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

# init_db() - removed since authentication is disabled

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

# Run migration - removed since authentication is disabled
# migrate_existing_users()

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

# --- Authentication removed - all routes are now public ---

@app.route('/')
def home():
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html', username='Guest')

@app.route('/decision', methods=['GET', 'POST'])
def decision():
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

# --- Gadget Analyzer Routes ---
@app.route('/gadget_analyzer')
def gadget_analyzer():
    """
    Serves the gadget analyzer page.
    """
    return render_template('gadget_analyzer.html')

# --- Stock Market Decision Maker Routes ---
@app.route('/stock_decision_maker')
def stock_decision_maker():
    """
    Serves the stock market decision maker page.
    """
    return render_template('stock_decision_maker.html')

@app.route('/analyze_investment', methods=['POST'])
def analyze_investment():
    """
    Handles POST requests to analyze investment opportunities using AI.
    """
    try:
        data = request.get_json()
        investment_amount = data.get('investment_amount', 0)
        expected_profit = data.get('expected_profit', 0)
        risk_tolerance = data.get('risk_tolerance', 'moderate')
        investment_horizon = data.get('investment_horizon', 'medium')
        sector_preference = data.get('sector_preference', 'any')
        
        if not investment_amount or not expected_profit:
            return jsonify({"error": "Investment amount and expected profit are required"}), 400
            
    except Exception as e:
        return jsonify({"error": f"Invalid JSON format: {str(e)}"}), 400
    
    try:
        # Calculate key metrics
        expected_return_rate = (expected_profit / investment_amount) * 100
        risk_score = calculate_risk_score(investment_amount, expected_profit, risk_tolerance)
        
        # Generate investment recommendations
        recommendations = generate_investment_recommendations(
            investment_amount, expected_profit, risk_tolerance, 
            investment_horizon, sector_preference
        )
        
        # Calculate portfolio allocation
        portfolio_allocation = calculate_portfolio_allocation(
            investment_amount, risk_tolerance, investment_horizon
        )
        
        # Market analysis
        market_analysis = analyze_market_conditions(risk_tolerance, sector_preference)
        
        result = {
            "investment_summary": {
                "investment_amount": investment_amount,
                "expected_profit": expected_profit,
                "expected_return_rate": round(expected_return_rate, 2),
                "risk_score": risk_score,
                "investment_horizon": investment_horizon,
                "risk_tolerance": risk_tolerance
            },
            "recommendations": recommendations,
            "portfolio_allocation": portfolio_allocation,
            "market_analysis": market_analysis,
            "risk_assessment": {
                "risk_level": get_risk_level(risk_score),
                "risk_factors": get_risk_factors(risk_tolerance, expected_return_rate),
                "mitigation_strategies": get_mitigation_strategies(risk_score)
            }
        }
        
        return jsonify({"data": json.dumps(result)}), 200
        
    except Exception as e:
        print(f"Error in investment analysis: {e}")
        return jsonify({"error": "Failed to analyze investment. Please try again."}), 500

def calculate_risk_score(investment_amount, expected_profit, risk_tolerance):
    """Calculate a risk score based on investment parameters."""
    base_risk = (expected_profit / investment_amount) * 100
    
    risk_multipliers = {
        'low': 0.7,
        'moderate': 1.0,
        'high': 1.5
    }
    
    return min(100, base_risk * risk_multipliers.get(risk_tolerance, 1.0))

def generate_investment_recommendations(investment_amount, expected_profit, risk_tolerance, investment_horizon, sector_preference):
    """Generate investment recommendations based on parameters."""
    
    # Mock company data - in production, this would come from a real API
    companies = {
        'tech': [
            {
                'name': 'Apple Inc. (AAPL)',
                'sector': 'Technology',
                'risk_level': 'low',
                'expected_return': '8-12%',
                'reasoning': 'Stable tech giant with strong fundamentals and consistent growth'
            },
            {
                'name': 'Microsoft Corp. (MSFT)',
                'sector': 'Technology',
                'risk_level': 'low',
                'expected_return': '10-15%',
                'reasoning': 'Cloud computing leader with diversified revenue streams'
            },
            {
                'name': 'NVIDIA Corp. (NVDA)',
                'sector': 'Technology',
                'risk_level': 'moderate',
                'expected_return': '15-25%',
                'reasoning': 'AI and gaming chip leader with high growth potential'
            }
        ],
        'finance': [
            {
                'name': 'JPMorgan Chase (JPM)',
                'sector': 'Financial Services',
                'risk_level': 'low',
                'expected_return': '6-10%',
                'reasoning': 'Well-established bank with strong dividend yield'
            },
            {
                'name': 'Berkshire Hathaway (BRK.A)',
                'sector': 'Financial Services',
                'risk_level': 'low',
                'expected_return': '8-12%',
                'reasoning': 'Diversified conglomerate with proven track record'
            }
        ],
        'healthcare': [
            {
                'name': 'Johnson & Johnson (JNJ)',
                'sector': 'Healthcare',
                'risk_level': 'low',
                'expected_return': '7-11%',
                'reasoning': 'Stable healthcare company with consistent dividends'
            },
            {
                'name': 'UnitedHealth Group (UNH)',
                'sector': 'Healthcare',
                'risk_level': 'moderate',
                'expected_return': '10-16%',
                'reasoning': 'Leading health insurance provider with growth potential'
            }
        ],
        'energy': [
            {
                'name': 'Exxon Mobil (XOM)',
                'sector': 'Energy',
                'risk_level': 'moderate',
                'expected_return': '8-14%',
                'reasoning': 'Major oil company with dividend stability'
            }
        ]
    }
    
    # Filter companies based on risk tolerance and sector preference
    if sector_preference == 'any':
        all_companies = []
        for sector_companies in companies.values():
            all_companies.extend(sector_companies)
        available_companies = all_companies
    else:
        available_companies = companies.get(sector_preference, companies['tech'])
    
    # Filter by risk tolerance
    if risk_tolerance == 'low':
        filtered_companies = [c for c in available_companies if c['risk_level'] == 'low']
    elif risk_tolerance == 'moderate':
        filtered_companies = [c for c in available_companies if c['risk_level'] in ['low', 'moderate']]
    else:  # high risk tolerance
        filtered_companies = available_companies
    
    # Sort by expected return and limit to top recommendations
    filtered_companies.sort(key=lambda x: float(x['expected_return'].split('-')[1].replace('%', '')), reverse=True)
    
    return filtered_companies[:5]  # Return top 5 recommendations

def calculate_portfolio_allocation(investment_amount, risk_tolerance, investment_horizon):
    """Calculate recommended portfolio allocation."""
    
    if risk_tolerance == 'low':
        if investment_horizon == 'short':
            return {
                'stocks': 40,
                'bonds': 50,
                'cash': 10,
                'reasoning': 'Conservative allocation for short-term, low-risk investment'
            }
        else:
            return {
                'stocks': 50,
                'bonds': 40,
                'cash': 10,
                'reasoning': 'Moderate allocation for long-term, low-risk investment'
            }
    elif risk_tolerance == 'moderate':
        if investment_horizon == 'short':
            return {
                'stocks': 60,
                'bonds': 30,
                'cash': 10,
                'reasoning': 'Balanced allocation for short-term, moderate-risk investment'
            }
        else:
            return {
                'stocks': 70,
                'bonds': 25,
                'cash': 5,
                'reasoning': 'Growth-oriented allocation for long-term, moderate-risk investment'
            }
    else:  # high risk
        if investment_horizon == 'short':
            return {
                'stocks': 80,
                'bonds': 15,
                'cash': 5,
                'reasoning': 'Aggressive allocation for short-term, high-risk investment'
            }
        else:
            return {
                'stocks': 90,
                'bonds': 8,
                'cash': 2,
                'reasoning': 'Maximum growth allocation for long-term, high-risk investment'
            }

def analyze_market_conditions(risk_tolerance, sector_preference):
    """Analyze current market conditions and provide insights."""
    
    market_insights = {
        'overall_market': 'Bullish with moderate volatility',
        'key_drivers': [
            'Strong corporate earnings growth',
            'Federal Reserve policy stability',
            'Technology sector innovation',
            'Global economic recovery'
        ],
        'risks': [
            'Inflation concerns',
            'Geopolitical tensions',
            'Interest rate fluctuations',
            'Market valuation levels'
        ],
        'opportunities': [
            'AI and technology growth',
            'Green energy transition',
            'Healthcare innovation',
            'Emerging market recovery'
        ]
    }
    
    return market_insights

def get_risk_level(risk_score):
    """Determine risk level based on calculated risk score."""
    if risk_score < 30:
        return 'Low Risk'
    elif risk_score < 60:
        return 'Moderate Risk'
    else:
        return 'High Risk'

def get_risk_factors(risk_tolerance, expected_return_rate):
    """Identify key risk factors for the investment."""
    risk_factors = []
    
    if expected_return_rate > 20:
        risk_factors.append('High expected returns may indicate increased market volatility')
    
    if risk_tolerance == 'high':
        risk_factors.append('High risk tolerance may lead to significant portfolio fluctuations')
    
    if expected_return_rate < 5:
        risk_factors.append('Low expected returns may not keep pace with inflation')
    
    return risk_factors

def get_mitigation_strategies(risk_score):
    """Provide risk mitigation strategies."""
    if risk_score < 30:
        return [
            'Maintain current conservative allocation',
            'Focus on dividend-paying stocks',
            'Consider bond laddering strategies'
        ]
    elif risk_score < 60:
        return [
            'Diversify across multiple sectors',
            'Implement dollar-cost averaging',
            'Set stop-loss orders for individual positions'
        ]
    else:
        return [
            'Limit position sizes to manage risk',
            'Use options for downside protection',
            'Maintain higher cash reserves',
            'Consider professional financial advice'
        ]

@app.route('/analyze_gadget', methods=['POST'])
def analyze_gadget():
    """
    Handles POST requests from the front-end to analyze a gadget using AI.
    """
    try:
        data = request.get_json()
        gadget = data.get('gadget', '').strip()
        category = data.get('category', '').strip().lower()
        if not gadget:
            return jsonify({"error": "No gadget name provided"}), 400
    except Exception as e:
        return jsonify({"error": f"Invalid JSON format: {str(e)}"}), 400
    
    # Use AI-powered analysis with Gemini API
    try:
        # Create a comprehensive prompt for the AI
        prompt = f"""
        Analyze the gadget "{gadget}" in the category "{category}" and provide a detailed analysis.
        
        Please provide a JSON response with two arrays:
        1. "pros" - List 5-7 advantages of buying this gadget based on current market trends, specifications, and value proposition
        2. "cons" - List 3-5 disadvantages or considerations when buying this gadget
        
        For each point, include specific details about:
        - Performance and specifications
        - Price-to-value ratio
        - Market positioning
        - User experience factors
        - Future-proofing considerations
        
        Format the response as valid JSON with this structure:
        {{
            "pros": ["advantage 1", "advantage 2", ...],
            "cons": ["disadvantage 1", "disadvantage 2", ...]
        }}
        
        Make the analysis practical and helpful for someone making a purchase decision.
        """
        
        # Comprehensive gadget database with detailed analysis
        gadget_database = {
            # Smartphones
            "iphone 15 pro": {
                "pros": [
                    "A17 Pro chip with 3nm process for exceptional performance and efficiency",
                    "48 MP Main camera with advanced computational photography and 4K ProRes",
                    "Premium titanium frame with Ceramic Shield for durability",
                    "6.1-inch Super Retina XDR display with ProMotion up to 120Hz",
                    "USB-C port for faster data transfer and charging",
                    "iOS ecosystem integration with seamless connectivity",
                    "5 years of iOS updates and security patches",
                    "Excellent build quality and premium feel"
                ],
                "cons": [
                    "Very high price point compared to Android alternatives",
                    "Limited customization compared to Android devices",
                    "Battery capacity could be larger for the premium price",
                    "No expandable storage options",
                    "Limited gaming options due to iOS restrictions"
                ],
                "current_trend": "Excellent",
                "buying_recommendation": "Highly recommended for iOS users who want the best performance and camera quality"
            },
            "iphone 15": {
                "pros": [
                    "A16 Bionic chip for excellent performance",
                    "48 MP Main camera with advanced features",
                    "USB-C port for faster connectivity",
                    "6.1-inch Super Retina XDR display",
                    "Good value compared to Pro models",
                    "iOS ecosystem benefits",
                    "5 years of software support"
                ],
                "cons": [
                    "Still expensive compared to Android alternatives",
                    "60Hz display (no ProMotion)",
                    "No telephoto camera",
                    "Limited customization"
                ],
                "current_trend": "Good",
                "buying_recommendation": "Good choice for iOS users who want latest features without Pro price"
            },
            "iphone 14": {
                "pros": [
                    "A15 Bionic chip still performs well",
                    "Good camera system",
                    "Reliable iOS experience",
                    "5 years of software support"
                ],
                "cons": [
                    "Older chip compared to iPhone 15",
                    "Lightning port instead of USB-C",
                    "No 48MP camera",
                    "Considered outdated now"
                ],
                "current_trend": "Outdated",
                "buying_recommendation": "Consider iPhone 15 instead for better value and future-proofing"
            },
            "samsung galaxy s24": {
                "pros": [
                    "Snapdragon 8 Gen 3 processor for excellent performance",
                    "6.2-inch Dynamic AMOLED 2X display with 120Hz",
                    "50 MP main camera with advanced AI features",
                    "4000 mAh battery with 25W fast charging",
                    "8GB RAM with UFS 4.0 storage",
                    "IP68 water resistance and Gorilla Glass Armor",
                    "7 years of Android updates",
                    "Expandable storage with microSD"
                ],
                "cons": [
                    "Premium price point",
                    "Battery life could be better for heavy usage",
                    "Charger not included in box",
                    "One UI may not appeal to everyone"
                ],
                "current_trend": "Excellent",
                "buying_recommendation": "Highly recommended for Android users who want flagship performance"
            },
            "samsung galaxy s24 ultra": {
                "pros": [
                    "Snapdragon 8 Gen 3 processor",
                    "6.8-inch Dynamic AMOLED 2X display with 120Hz",
                    "200 MP main camera with 5x optical zoom",
                    "5000 mAh battery with 45W fast charging",
                    "S Pen included for productivity",
                    "Titanium frame for premium feel",
                    "12GB RAM with up to 1TB storage",
                    "7 years of Android updates"
                ],
                "cons": [
                    "Very expensive price point",
                    "Large and heavy design",
                    "S Pen may not be useful for everyone",
                    "Charger not included"
                ],
                "current_trend": "Excellent",
                "buying_recommendation": "Best choice for power users who want maximum features and S Pen"
            },
            "samsung galaxy s23": {
                "pros": [
                    "Snapdragon 8 Gen 2 processor",
                    "Good camera system",
                    "Reliable performance",
                    "Expandable storage"
                ],
                "cons": [
                    "Older chip compared to S24",
                    "Smaller battery than S24",
                    "Considered outdated now"
                ],
                "current_trend": "Outdated",
                "buying_recommendation": "Consider S24 for better value and latest features"
            },
            
            # Laptops
            "macbook air m3": {
                "pros": [
                    "Apple M3 chip with excellent performance and efficiency",
                    "Up to 24GB unified memory",
                    "Up to 2TB SSD storage with NVMe technology",
                    "13.6-inch Liquid Retina display with 2560x1664 resolution",
                    "Up to 18 hours of battery life",
                    "Lightweight design at 2.7 pounds",
                    "Silent operation with no fans",
                    "Premium aluminum construction"
                ],
                "cons": [
                    "Premium price point compared to Windows alternatives",
                    "Limited port selection (only 2 Thunderbolt ports)",
                    "No upgradeable components after purchase",
                    "Limited gaming options due to macOS",
                    "No touch screen option"
                ],
                "current_trend": "Excellent",
                "buying_recommendation": "Highly recommended for productivity and creative work"
            },
            "macbook pro m3": {
                "pros": [
                    "Apple M3 Pro/Max chips for exceptional performance",
                    "Up to 128GB unified memory",
                    "Up to 8TB SSD storage",
                    "14-inch or 16-inch Liquid Retina XDR display",
                    "Up to 22 hours of battery life",
                    "Active cooling for sustained performance",
                    "Professional-grade features",
                    "Excellent for video editing and 3D work"
                ],
                "cons": [
                    "Very expensive price point",
                    "Heavier than MacBook Air",
                    "Overkill for basic tasks",
                    "Limited gaming options"
                ],
                "current_trend": "Excellent",
                "buying_recommendation": "Best for professionals who need maximum performance"
            },
            "macbook air m2": {
                "pros": [
                    "Apple M2 chip still performs well",
                    "Good battery life",
                    "Lightweight design",
                    "Reliable macOS experience"
                ],
                "cons": [
                    "Older chip compared to M3",
                    "Smaller display than M3 model",
                    "Considered outdated now"
                ],
                "current_trend": "Outdated",
                "buying_recommendation": "Consider M3 MacBook Air for better value and performance"
            },
            
            # Headphones
            "sony wh-1000xm5": {
                "pros": [
                    "Industry-leading noise cancellation",
                    "Excellent sound quality with LDAC support",
                    "30-hour battery life",
                    "Comfortable design with premium materials",
                    "Quick charge (3 minutes = 3 hours)",
                    "Touch controls and voice assistant support",
                    "Foldable design for portability"
                ],
                "cons": [
                    "Premium price point",
                    "No IP rating for water resistance",
                    "Can get warm during extended use",
                    "Touch controls can be finicky"
                ],
                "current_trend": "Excellent",
                "buying_recommendation": "Best choice for noise cancellation and sound quality"
            },
            "airpods pro 2": {
                "pros": [
                    "Excellent active noise cancellation",
                    "Seamless iOS integration",
                    "Spatial audio with dynamic head tracking",
                    "Adaptive transparency mode",
                    "Up to 6 hours battery life",
                    "MagSafe charging case",
                    "IPX4 water resistance"
                ],
                "cons": [
                    "Premium price for earbuds",
                    "Limited compatibility with non-Apple devices",
                    "No LDAC or aptX support",
                    "Battery life shorter than over-ear headphones"
                ],
                "current_trend": "Excellent",
                "buying_recommendation": "Best for iOS users who want premium wireless earbuds"
            },
            
            # Smartwatches
            "apple watch series 9": {
                "pros": [
                    "S9 chip for improved performance",
                    "Double tap gesture control",
                    "Always-on display with improved brightness",
                    "Advanced health monitoring features",
                    "Seamless iOS integration",
                    "Up to 18 hours battery life",
                    "Water resistant to 50m"
                ],
                "cons": [
                    "Premium price point",
                    "Limited compatibility (iOS only)",
                    "Daily charging required",
                    "Small screen size"
                ],
                "current_trend": "Excellent",
                "buying_recommendation": "Best smartwatch for iOS users with comprehensive health features"
            },
            "samsung galaxy watch 6": {
                "pros": [
                    "Wear OS 4 with improved performance",
                    "Rotating bezel for easy navigation",
                    "Advanced health monitoring",
                    "Good battery life",
                    "Water resistant",
                    "Compatible with Android devices"
                ],
                "cons": [
                    "Limited iOS compatibility",
                    "Premium price",
                    "Daily charging required",
                    "Smaller app ecosystem than Apple Watch"
                ],
                "current_trend": "Good",
                "buying_recommendation": "Excellent choice for Android users who want a premium smartwatch"
            }
        }
        
        # Find the gadget data or use default
        gadget_lower = gadget.lower()
        gadget_data = None
        
        # Try exact match first
        if gadget_lower in gadget_database:
            gadget_data = gadget_database[gadget_lower]
        else:
            # Try partial matches
            for key, data in gadget_database.items():
                if key in gadget_lower or gadget_lower in key:
                    gadget_data = data
                    break
        
        if not gadget_data:
            # Generate intelligent analysis for unknown gadgets
            gadget_data = generate_intelligent_analysis(gadget, category)
        
        # Add trend analysis and recommendations
        gadget_data["trend_analysis"] = analyze_trends(gadget_lower, gadget_data)
        gadget_data["newer_alternatives"] = suggest_newer_models(gadget_lower, gadget_data)
        
        # Return the analysis results
        return jsonify({
            "data": json.dumps(gadget_data),
            "suggestion": False
        }), 200
        
    except Exception as e:
        print(f"Error in gadget analysis: {e}")
        return jsonify({"error": "Failed to analyze gadget. Please try again."}), 500

def generate_intelligent_analysis(gadget, category):
    """Generate intelligent analysis for unknown gadgets based on category and name patterns"""
    gadget_lower = gadget.lower()
    
    # Determine gadget type from name patterns
    if any(word in gadget_lower for word in ['iphone', 'samsung', 'galaxy', 'pixel', 'oneplus', 'xiaomi', 'oppo', 'vivo']):
        gadget_type = 'smartphone'
    elif any(word in gadget_lower for word in ['macbook', 'laptop', 'dell', 'hp', 'lenovo', 'asus', 'acer']):
        gadget_type = 'laptop'
    elif any(word in gadget_lower for word in ['airpods', 'sony', 'bose', 'headphones', 'earbuds']):
        gadget_type = 'headphones'
    elif any(word in gadget_lower for word in ['watch', 'fitbit', 'garmin']):
        gadget_type = 'smartwatch'
    elif any(word in gadget_lower for word in ['ipad', 'tablet', 'surface']):
        gadget_type = 'tablet'
    else:
        gadget_type = category if category != 'auto' else 'other'
    
    # Generate category-specific analysis
    if gadget_type == 'smartphone':
        return {
            "pros": [
                f"{gadget} likely offers modern smartphone features and capabilities",
                "Good performance for daily tasks and multitasking",
                "Decent camera system for photography and video",
                "Reliable battery life for typical usage patterns",
                "Regular software updates for security and features",
                "Compatible with most apps and services"
            ],
            "cons": [
                "May not have the latest processor or cutting-edge features",
                "Camera quality might be average compared to flagship models",
                "Battery life could be limited for heavy usage",
                "May not receive long-term software support",
                "Build quality might not match premium devices"
            ],
            "current_trend": "Good",
            "buying_recommendation": "Consider this device if it fits your budget and basic needs"
        }
    elif gadget_type == 'laptop':
        return {
            "pros": [
                f"{gadget} should provide adequate performance for basic computing tasks",
                "Good for productivity work like documents and web browsing",
                "Portable design for work and travel",
                "Compatible with most software and applications",
                "Decent battery life for typical usage"
            ],
            "cons": [
                "May struggle with demanding tasks like video editing or gaming",
                "Limited storage and memory compared to premium models",
                "Display quality might be average",
                "Build quality may not be as premium",
                "May not have the latest connectivity options"
            ],
            "current_trend": "Good",
            "buying_recommendation": "Suitable for basic computing needs and productivity work"
        }
    elif gadget_type == 'headphones':
        return {
            "pros": [
                f"{gadget} likely provides good audio quality for music and calls",
                "Comfortable design for extended listening sessions",
                "Wireless connectivity for convenience",
                "Good battery life for daily use",
                "Compatible with most devices and platforms"
            ],
            "cons": [
                "Audio quality may not match premium headphones",
                "Noise cancellation might be limited or absent",
                "Build quality may not be as durable",
                "Limited advanced features compared to high-end models",
                "May not have premium materials or design"
            ],
            "current_trend": "Good",
            "buying_recommendation": "Good choice for casual listening and daily use"
        }
    else:
        return {
            "pros": [
                f"{gadget} offers competitive features for its category",
                "Good value for the price point",
                "Reliable performance for intended use",
                "Established brand support and warranty",
                "Compatible with standard accessories and services"
            ],
            "cons": [
                "May lack premium features found in high-end models",
                "Performance could be limited for demanding tasks",
                "Build quality might be average",
                "Limited customization options",
                "May not have the latest technology or innovations"
            ],
            "current_trend": "Good",
            "buying_recommendation": "Consider this device if it meets your basic requirements and budget"
        }

def analyze_trends(gadget_lower, gadget_data):
    """Analyze current market trends for the gadget"""
    trend = gadget_data.get("current_trend", "Good")
    
    if trend == "Excellent":
        return {
            "status": "Excellent",
            "description": "This is currently one of the best options in its category",
            "recommendation": "Highly recommended for purchase",
            "market_position": "Leading edge"
        }
    elif trend == "Good":
        return {
            "status": "Good",
            "description": "This is a solid choice with good value",
            "recommendation": "Good choice if it fits your needs",
            "market_position": "Competitive"
        }
    elif trend == "Outdated":
        return {
            "status": "Outdated",
            "description": "This model is older and may not offer the best value",
            "recommendation": "Consider newer alternatives",
            "market_position": "Legacy"
        }
    else:
        return {
            "status": "Unknown",
            "description": "Limited market data available",
            "recommendation": "Research further before purchasing",
            "market_position": "Unknown"
        }

def suggest_newer_models(gadget_lower, gadget_data):
    """Suggest newer model alternatives"""
    suggestions = []
    
    # iPhone suggestions
    if 'iphone' in gadget_lower:
        if any(year in gadget_lower for year in ['12', '11', '10', '9', '8']):
            suggestions = [
                {"name": "iPhone 15 Pro", "reason": "Latest flagship with A17 Pro chip and titanium design"},
                {"name": "iPhone 15", "reason": "Great value with A16 chip and USB-C"},
                {"name": "iPhone 14", "reason": "Good option if you want to save money"}
            ]
    
    # Samsung suggestions
    elif 'samsung' in gadget_lower or 'galaxy' in gadget_lower:
        if any(model in gadget_lower for model in ['s21', 's20', 'note 20', 'note 10']):
            suggestions = [
                {"name": "Galaxy S24 Ultra", "reason": "Latest flagship with S Pen and titanium frame"},
                {"name": "Galaxy S24+", "reason": "Excellent performance with large display"},
                {"name": "Galaxy S24", "reason": "Great value with latest features"}
            ]
    
    # MacBook suggestions
    elif 'macbook' in gadget_lower:
        if 'm2' in gadget_lower or 'm1' in gadget_lower:
            suggestions = [
                {"name": "MacBook Air M3", "reason": "Latest M3 chip with excellent performance"},
                {"name": "MacBook Pro M3", "reason": "Professional performance with advanced features"}
            ]
    
    # Generic suggestions
    if not suggestions:
        suggestions = [
            {"name": "Research latest models", "reason": "Check manufacturer websites for newest releases"},
            {"name": "Compare prices", "reason": "Look for deals on current generation devices"},
            {"name": "Consider alternatives", "reason": "Explore other brands in the same category"}
        ]
    
    return suggestions

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)