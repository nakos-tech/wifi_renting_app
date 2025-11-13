from flask import Flask, render_template, session, redirect, url_for, flash, jsonify, request
# IMPORTANT: If this file (e.g., app.py) is your main application file,
# and LoginForm/SignUpForm are defined within *this same file*,
# then 'from app import LoginForm, SignUpForm' will cause a circular import.
# In that case, remove this line and define LoginForm/SignUpForm directly here,
# or import them from a separate file (e.g., 'from forms.py import LoginForm, SignUpForm').
from app import LoginForm, SignUpForm # Assuming app.py is where LoginForm and SignUpForm are defined
from flask_wtf.csrf import CSRFProtect
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os
from dotenv import load_dotenv

from admin import admin_bp

# M-Pesa specific imports
import requests
from requests.auth import HTTPBasicAuth
import base64
from datetime import datetime
import json # For pretty printing JSON in callbacks

# Mikrotik API imports
import routeros_api

# WTForms imports for SignUpForm modification (if SignUpForm is defined here)
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo, Regexp

from flask_wtf.csrf import CSRFProtect

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'a_very_secret_key_if_not_set_in_env') # Get from env or use default
csrf = CSRFProtect(app)  # Enable CSRF protection
app.register_blueprint(admin_bp, url_prefix='/admin')

# --- M-Pesa Configuration (Loaded from .env for best practice) ---
# Ensure these variables are set in your .env file:
# CONSUMER_KEY="your_consumer_key"
# CONSUMER_SECRET="your_consumer_secret"
# BUSINESS_SHORTCODE="your_business_shortcode"
# PASSKEY="your_passkey"
# CALLBACK_BASE_URL="https://your-ngrok-url.ngrok.io" # Your ngrok public URL
# IMPORTANT: This MUST be the active HTTPS ngrok URL and registered in Daraja portal.

CONSUMER_KEY = os.getenv("CONSUMER_KEY")
CONSUMER_SECRET = os.getenv("CONSUMER_SECRET")
BUSINESS_SHORTCODE = os.getenv("BUSINESS_SHORTCODE")
PASSKEY = os.getenv("PASSKEY")
CALLBACK_BASE_URL = os.getenv("CALLBACK_BASE_URL") # Use consistent variable name

# --- Mikrotik Router Details (add these to your .env or configure securely) ---
MIKROTIK_HOST = os.getenv("MIKROTIK_HOST", "192.168.88.1") # Default Mikrotik IP
MIKROTIK_USERNAME = os.getenv("MIKROTIK_USERNAME", "admin")
MIKROTIK_PASSWORD = os.getenv("MIKROTIK_PASSWORD", "") # Use the password you set

# --- Daraja API Endpoints ---
TOKEN_URL = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
STK_PUSH_URL = "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest"

app.config['SECRET_KEY'] = 'my_self_I'

# Initialize CSRF protection
csrf = CSRFProtect(app)
csrf.exempt(admin_bp)  # Disable CSRF protection for the account blueprint if needed

# Disable CSRF protection for specific admin API endpoints


# Register the admin blueprint
def init_db():
    conn = sqlite3.connect('wifi_listings.db')
    cursor = conn.cursor()

    # Create the wifi_plans table

    # Create the vouchers table to store generated voucher codes
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vouchers (
            voucher_code TEXT PRIMARY KEY,
            plan_duration TEXT NOT NULL,
            is_used BOOLEAN NOT NULL CHECK(is_used IN (0, 1)) DEFAULT 0,
            generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (plan_duration) REFERENCES wifi_plans (duration)
        );
    ''')

    conn.commit()
    conn.close()
# --- Helper Function to Get M-Pesa Access Token ---
def getAccesstoken():
    """Fetches the access token from Safaricom Daraja API."""
    print("\n--- Attempting to get M-Pesa access token ---")
    # Debugging: Print the credentials being used (first few chars for security)
    print(f"Using CONSUMER_KEY: {CONSUMER_KEY[:5]}... and CONSUMER_SECRET: {CONSUMER_SECRET[:5]}...")
    
    credentials = f"{CONSUMER_KEY}:{CONSUMER_SECRET}"
    encoded_credentials = base64.b64encode(credentials.encode()).decode()

    headers = {
        "Authorization": f"Basic {encoded_credentials}",
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36" # Added User-Agent
    }

    response = None # Initialize response to None
    try:
        response = requests.get(TOKEN_URL, headers=headers)
        response.raise_for_status() # This will raise HTTPError for 4xx/5xx responses (e.g., 403 Forbidden)
        
        # Explicitly check Content-Type header
        content_type = response.headers.get('Content-Type', '')
        if 'application/json' not in content_type:
            print(f"Warning: Access token endpoint returned non-JSON Content-Type: {content_type}")
            print(f"Response content: {response.text}")
            return None

        token_data = response.json() # This is where json.JSONDecodeError could occur
        
        # Explicitly check if response.json() returned None (e.g., for empty body)
        if token_data is None:
            print("Error: response.json() returned None for access token request.")
            print(f"Raw response text: {response.text}")
            return None

        access_token = token_data.get("access_token")
        if access_token:
            print("M-Pesa Access Token retrieved successfully.")
            return access_token
        else:
            print(f"Error: Access token not found in response: {token_data}")
            # Also print if there's an 'error' or 'message' key in token_data
            if isinstance(token_data, dict): # Ensure it's a dict before trying .get()
                if 'error' in token_data:
                    print(f"Safaricom API Error: {token_data.get('error')}")
                if 'message' in token_data:
                    print(f"Safaricom API Message: {token_data.get('message')}")
            return None
    except (requests.exceptions.RequestException, json.JSONDecodeError) as e: # Catch both request errors and JSON decoding errors
        print(f"Error getting M-Pesa access token: {e}")
        if response is not None:
            print(f"Response status code: {response.status_code}")
            print(f"Response content: {response.text}") # Print the actual response content for debugging
        return None

# --- Mikrotik API Connection Function ---
def connect_to_mikrotik():
    try:
        connection = routeros_api.RouterOsApiPool(
            MIKROTIK_HOST,
            username=MIKROTIK_USERNAME,
            password=MIKROTIK_PASSWORD,
            port=8728, # Use 8729 for api-ssl
            use_ssl=False, # Set to True if using api-ssl and proper certs
            plaintext_login=True # Required for RouterOS v6.43+ if not using SSL with proper certs
        )
        api = connection.get_api()
        print(f"Successfully connected to Mikrotik router at {MIKROTIK_HOST}")
        return api, connection
    except Exception as e:
        print(f"Error connecting to Mikrotik: {e}")
        return None, None

# --- Database Initialization ---
def create_transactions_table():
    conn = sqlite3.connect('members.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            checkout_request_id TEXT UNIQUE NOT NULL,
            phone_number TEXT NOT NULL,
            wifi_duration TEXT NOT NULL,
            amount REAL NOT NULL,
            status TEXT NOT NULL, -- PENDING, SUCCESSFUL, FAILED
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()
    print("Ensured 'transactions' table exists in members.db")

def generate_password():
    # generate mpesa password 
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    data = f"{BUSINESS_SHORTCODE}{PASSKEY}{timestamp}"
    encoded = base64.b64encode(data.encode())
    return encoded.decode('utf-8')

def initiate_stk_push(phone, amount, account_reference, transaction_desc):
    # initiate stk push for payment
    access_token = getAccesstoken()
    if not access_token:
        print("error: failed to get access_token")

    password, timestamp = generate_password()

    if phone.startswith("0"):
        phone = "254" + phone[1:]  # Convert 07XX to 254XXXXXXXXX

    elif phone.startswith("+254"):
        phone = phone[1:]  # removes the '+' sign

    headers = {
        "Authorization" : f"Bearer {access_token}",
        "content-type": "application/json"
    }

    payload = {
        "BusinessShortCode": BUSINESS_SHORTCODE, 
        "Password": password, 
        "Timestamp": timestamp,
        "TransactionType": "CustomerPayBillOnline", 
        "Amount": int(amount), 
        "partyA": phone,
        "partyB": BUSINESS_SHORTCODE,
        "callBackURL": CALLBACK_BASE_URL,
        "AccountReference": account_reference,
        "TransactionDesc": transaction_desc
    }

    try: 
        response = requests.post(STK_PUSH_URL, json=payload, headers=headers)
        return response.json()
    except Exception as e:
        app.logger.error(f"Error inititiating STK Push: {e}")
        return {"error" : str(e)}

# --- Custom SignUpForm Definition (Moved here for direct modification) ---
# Assuming LoginForm is also defined similarly or imported from 'app'
class SignUpForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=5, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    # Updated Regexp to accept country codes (starts with '+', followed by 1 to 15 digits)
    phone = StringField('Phone Number', validators=[
        DataRequired(),
        Regexp(r'^\+\d{1,15}$', message="Phone number must start with '+' and contain 1-15 digits (e.g., +2547XXXXXXXX)")
    ])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message="Passwords must match")
    ])
    submit = SubmitField('Sign Up')

# --- Main Application Routes ---

@app.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
    form = SignUpForm()

    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        phone = form.phone.data # This will now contain the full phone number from the combined input
        password_hash = generate_password_hash(form.password.data)

        try:
            conn = sqlite3.connect('members.db')
            cursor = conn.cursor()

            # Create table if not exists
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    phone TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL
                )
            ''')

            # Insert user
            cursor.execute(
                "INSERT INTO users (username, email, phone, password) VALUES ( ?, ?, ?, ?)",
                (username, email, phone, password_hash)
            )

            conn.commit()
            flash("Sign-up successful! Please log in.", "success")
            return redirect(url_for('login'))

        except sqlite3.IntegrityError:
            flash("Username, email, or phone already exists. Try a different one.", "danger")

        finally:
            conn.close()

    return render_template('sign_up.html', form=form)

@app.route('/')
def home():

    conn = sqlite3.connect('wifi_listings.db')
    cursor = conn.cursor()
    cursor.execute("SELECT wifi_duration, amount, devices FROM wifi_listings")
    wifi_plans = cursor.fetchall()
    return render_template('index.html',  wifi_plans=wifi_plans)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        conn = sqlite3.connect('members.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        if user and check_password_hash(user[4], password):
            session['user'] = username
            flash(f"Welcome back, {username}!", "success")
            if username == 'admin':
                return redirect(url_for('admin_bp.admin_panel'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password", "danger")
    return render_template('login.html', form=form)

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        flash("Please log in to view the dashboard.", "warning")
        return redirect(url_for('login'))

    username = session['user']
    user_phone = None
    try:
        conn = sqlite3.connect('members.db')
        cursor = conn.cursor()
        cursor.execute("SELECT phone FROM users WHERE username = ?", (username,))
        user_data = cursor.fetchone()
        if user_data:
            user_phone = user_data[0] # Get the phone number
        conn.close()
    except Exception as e:
        print(f"Error fetching user phone for dashboard: {e}")
        flash("Could not retrieve user phone number.", "danger")


    conn = sqlite3.connect('wifi_listings.db')
    cursor = conn.cursor()
    cursor.execute("SELECT wifi_duration, amount, devices FROM wifi_listings")
    wifi_plans = cursor.fetchall()
    conn.close()

    # Pass user_phone to the template
    return render_template("dashboard.html", wifi_plans=wifi_plans, user_phone=user_phone)

@app.route('/logout')
def logout():
    session.pop('user', None)  # Remove user from session
    flash("You have been logged out.", "info")
    return redirect(url_for('home')) 

@app.route("/initiate_payment", methods=["POST"])
def initiate_wifi_payment():
    # initiate wifi packages via mpesa
    try:
        data = request.get_json()
        
        # validate the required data availability

        phone = data.get("phone")
        wifi_duration = data.get("wifi_duration")
        amount = data.get("amount")
        devices = data.get("devices", 1)

        if not all(phone, wifi_duration, amount):
            return jsonify ({
                "success": False
                "message": "missing required fields: phone, wifi_duration, and amount are required"
            }), phone

        if not phone.startswith("254"):
            return jsonify({
                "success": False
                "message": "Invalid phone number format"
            }), 400

        try:
            amount = float(amount)
            if amount <= 1:
                raise ValueError
            except (ValueError, TypeError):
                return jsonify({
                    "success": False,
                    "message": "Invalid amount"
                }), 400

        #  get or create user 
        user = User.query.filter_by(phone=phone).first()
        if not user:
            user = User(phone=phone)
            db.session.add(user)
            db.session.commit()

        # create Wifi package record 
        wifi_package = WifiPackage(
            user_id=user_id,
            duration=wifi_duration,
            amount=amount,
            devices=devices,
            status="PENDING" 

        )
        db.session.add(wifi_package)
        db.session.commit()


@app.route("/pay", methods=["POST"])
def initiate_payment():
    if 'user' not in session:
        return jsonify({"error": "Unauthorized. Please log in."}), 401
    
    # --- Debugging: Print raw request data and headers ---
    print("\n--- Received /pay POST request ---")
    print(f"Request Headers: {request.headers}")
    print(f"Raw Request Data: {request.data}")
    # --- End Debugging ---
    
    try:
        data = request.get_json()
    except Exception as e:
        print(f"Error parsing JSON from request body: {e}")
        print(f"Raw body content that failed parsing: {request.data.decode('utf-8')}")
        return jsonify({"error": "Invalid JSON in request body."}), 400
    
    if data is None:
        print("request.get_json() returned None. Check Content-Type header or empty body.")
        return jsonify({"error": "Request body is empty or not valid JSON."}), 400
    
    wifi_duration = data.get("wifi_duration")  # Get wifi_duration from the request body
    phone = data.get("phone")  # Get phone from the request body
    
    # --- Debugging: Print extracted data ---
    print(f"Extracted wifi_duration: '{wifi_duration}'")
    print(f"Extracted phone: '{phone}'")
    # --- End Debugging ---
    
    if not wifi_duration or not phone:
        print(f"Validation failed: wifi_duration='{wifi_duration}', phone='{phone}'")
        return jsonify({"error": "Missing 'wifi_duration' or 'phone' in request body"}), 400
    
    # Enhanced phone number validation
    phone = phone.strip()
    
    # Convert phone to M-Pesa format (254XXXXXXXXX)
    if phone.startswith("+254"):
        mpesa_phone = phone[1:]  # Remove '+' -> 254XXXXXXXXX
    elif phone.startswith("0"):
        mpesa_phone = "254" + phone[1:]  # Convert 07XX to 254XXXXXXXXX
    elif phone.startswith("254"):
        mpesa_phone = phone  # Already in correct format
    else:
        return jsonify({"error": "Invalid phone number format. Use 254XXXXXXXXX, +254XXXXXXXXX, or 07XXXXXXXX"}), 400
    
    # Final validation for M-Pesa format
    if not mpesa_phone.isdigit() or len(mpesa_phone) != 12 or not mpesa_phone.startswith("254"):
        return jsonify({"error": "Invalid M-Pesa phone number. Must be 12 digits starting with 254."}), 400
    
    # Retrieve amount from wifi_listings.db based on wifi_duration
    amount = None
    try:
        conn = sqlite3.connect('wifi_listings.db')
        cursor = conn.cursor()
        cursor.execute("SELECT amount FROM wifi_listings WHERE wifi_duration = ?", (wifi_duration,))
        result = cursor.fetchone()
        if result:
            amount = result[0]
        conn.close()
    except Exception as e:
        print(f"Error fetching amount from wifi_listings: {e}")
        return jsonify({"error": "Failed to retrieve plan amount from database."}), 500
    
    if amount is None:
        return jsonify({"error": f"WiFi plan '{wifi_duration}' not found."}), 404
    
    try:
        amount = int(amount)  # Ensure amount is an integer
        if amount <= 0:
            return jsonify({"error": "Amount must be a positive number"}), 400
    except ValueError:
        return jsonify({"error": "Invalid amount format from database."}), 500
    
    # --- Debugging: Print final values before M-Pesa call ---
    print(f"Final M-Pesa phone: '{mpesa_phone}'")
    print(f"Final amount: {amount}")
    print(f"WiFi duration: '{wifi_duration}'")
    # --- End Debugging ---
    
    # Get M-Pesa access token
    access_token = None
    try:
        access_token = getAccesstoken()  # Call the helper function
    except Exception as e:
        print(f"CRITICAL ERROR: Exception during getAccesstoken(): {e}")
        return jsonify({"error": "Critical error during M-Pesa token retrieval."}), 500

    if not access_token:
        # If token retrieval failed, getAccesstoken() would have already printed details
        return jsonify({"error": "Failed to get M-Pesa access token. Check server logs for details."}), 500

    # Prepare STK Push request
    headers = { 
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36"
    }
    
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    password_str = f"{BUSINESS_SHORTCODE}{PASSKEY}{timestamp}"
    encoded_password = base64.b64encode(password_str.encode('utf-8')).decode('utf-8')

    # Strip trailing slash from CALLBACK_BASE_URL to prevent double slashes
    clean_callback_base_url = CALLBACK_BASE_URL.rstrip('/')

    stk_payload = {
        "BusinessShortCode": BUSINESS_SHORTCODE,
        "Password": encoded_password,
        "Timestamp": timestamp,
        "TransactionType": "CustomerPayBillOnline",
        "Amount": amount,
        "PartyA": mpesa_phone,
        "PartyB": BUSINESS_SHORTCODE,
        "PhoneNumber": mpesa_phone,
        "CallBackURL": f"{clean_callback_base_url}/lnmo-callback",
        "AccountReference": f"WiFi_{wifi_duration}",
        "TransactionDesc": f"WiFi Plan Payment for {wifi_duration} - {amount} KES"
    }

    # --- Debugging: Print the final payload sent to Safaricom ---
    print("\n--- Final STK Push Payload to Safaricom ---")
    print(json.dumps(stk_payload, indent=4))
    # --- End Debugging ---

    try:
        # Make STK Push request to M-Pesa
        response = requests.post(STK_PUSH_URL, json=stk_payload, headers=headers)
        
        # Log response details for debugging
        print(f"STK Push Response Status: {response.status_code}")
        print(f"STK Push Response Headers: {response.headers}")
        print(f"STK Push Response Content: {response.text}")
        
        response.raise_for_status()
        mpesa_response_json = response.json()
        
        print("STK Push request sent successfully. Response from Safaricom:")
        print(json.dumps(mpesa_response_json, indent=4))

        # Check if the response indicates success
        response_code = mpesa_response_json.get('ResponseCode')
        if response_code == "0":
            # Extract CheckoutRequestID from M-Pesa response for transaction tracking
            checkout_request_id = mpesa_response_json.get('CheckoutRequestID')
            if checkout_request_id:
                try:
                    # Store transaction details in database
                    conn = sqlite3.connect('members.db')
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO transactions (checkout_request_id, phone_number, wifi_duration, amount, status, created_at) 
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (checkout_request_id, mpesa_phone, wifi_duration, amount, 'PENDING', datetime.now()))
                    conn.commit()
                    conn.close()
                    print(f"Transaction recorded: {checkout_request_id}, Status: PENDING")
                except Exception as db_error:
                    print(f"Failed to record transaction in database: {db_error}")
                    # Don't fail the whole request if database logging fails
            else:
                print("Warning: CheckoutRequestID not found in M-Pesa response.")
        
        # Return the M-Pesa response to the frontend
        return jsonify(mpesa_response_json), 200
        
    except requests.exceptions.HTTPError as e:
        print(f"HTTP Error during STK Push: {e}")
        print(f"Response status code: {response.status_code}")
        print(f"Response content: {response.text}")
        
        # Try to parse error response from M-Pesa
        try:
            error_response = response.json()
            error_message = error_response.get('errorMessage', 'Unknown M-Pesa error')
            return jsonify({
                "ResponseCode": "1",
                "ResponseDescription": f"M-Pesa Error: {error_message}",
                "error": f"Payment failed: {error_message}"
            }), 400
        except:
            return jsonify({
                "ResponseCode": "1", 
                "ResponseDescription": "M-Pesa service error",
                "error": f"Payment failed with status {response.status_code}"
            }), 500
            
    except requests.exceptions.RequestException as e:
        print(f"Network error during STK Push: {e}")
        return jsonify({
            "ResponseCode": "1",
            "ResponseDescription": "Network error during payment",
            "error": "Failed to connect to M-Pesa service. Please try again."
        }), 500
        
    except Exception as e:
        print(f"Unexpected error during M-Pesa payment initiation: {e}")
        return jsonify({
            "ResponseCode": "1", 
            "ResponseDescription": "Payment initiation failed",
            "error": "An unexpected error occurred. Please try again."
        }), 500
# Consume the M-Pesa callback
@app.route("/lnmo-callback", methods=["POST"])
def incoming_json():
    """
    Receives M-Pesa STK Push callback results.
    After successful payment, activate the user on Mikrotik.
    """
    try:
        data = request.get_json()
        
        if data:
            print("\n--- Received M-Pesa Callback Data ---")
            print(json.dumps(data, indent=4))

            checkout_request_id = None
            if 'Body' in data and 'stkCallback' in data['Body']:
                stk_callback = data['Body']['stkCallback']
                result_code = stk_callback.get('ResultCode')
                result_desc = stk_callback.get('ResultDesc')
                checkout_request_id = stk_callback.get('CheckoutRequestID') # Get CheckoutRequestID from callback

                print(f"Callback Result Code: {result_code}")
                print(f"Callback Result Description: {result_desc}")
                print(f"Callback CheckoutRequestID from stkCallback: {checkout_request_id}") # Added log

                # Update transaction status in DB
                conn = sqlite3.connect('members.db')
                cursor = conn.cursor()
                
                transaction_status = 'FAILED' if result_code != 0 else 'SUCCESSFUL'
                
                if checkout_request_id:
                    cursor.execute(
                        "UPDATE transactions SET status = ? WHERE checkout_request_id = ?",
                        (transaction_status, checkout_request_id)
                    )
                    conn.commit()
                    # Check if any row was actually updated
                    if cursor.rowcount > 0:
                        print(f"Transaction {checkout_request_id} updated to {transaction_status} in DB.")
                    else:
                        print(f"Warning: No transaction found with CheckoutRequestID {checkout_request_id} to update.")
                else:
                    print("Warning: CheckoutRequestID not found in callback payload for status update. Cannot update transaction status.")

                if result_code == 0:
                    print("M-Pesa Transaction Successful! Now attempting to activate user on Mikrotik.")
                    
                    # Retrieve original transaction details from database
                    wifi_duration = None
                    mpesa_phone_for_activation = None
                    if checkout_request_id:
                        cursor.execute(
                            "SELECT phone_number, wifi_duration FROM transactions WHERE checkout_request_id = ?",
                            (checkout_request_id,)
                        )
                        transaction_record = cursor.fetchone()
                        if transaction_record:
                            mpesa_phone_for_activation = transaction_record[0]
                            wifi_duration = transaction_record[1]
                            print(f"Retrieved transaction details: Phone={mpesa_phone_for_activation}, Duration={wifi_duration}")
                        else:
                            print(f"Error: No transaction record found for CheckoutRequestID: {checkout_request_id}")
                    
                    conn.close() # Close connection after DB operations

                    if wifi_duration and mpesa_phone_for_activation:
                        api, connection = connect_to_mikrotik()
                        if api:
                            try:
                                hotspot_username = mpesa_phone_for_activation # Using phone number as hotspot username
                                
                                # Convert wifi_duration string (e.g., "1 Hour") to Mikrotik uptime format (e.g., "1h")
                                duration_map = {
                                    "1 Hour": "1h",
                                    "2 Hours": "2h",
                                    "6 Hours": "6h",
                                    "1 Day": "1d",
                                    "3 Days": "3d",
                                    # Add more mappings as per your wifi_plans
                                }
                                mikrotik_uptime = duration_map.get(wifi_duration, "1h") # Default to 1 hour if not found

                                # Check if user already exists in Hotspot users
                                existing_users = api.get_resource('/ip/hotspot/user').get(name=hotspot_username)

                                if existing_users:
                                    user_id = existing_users[0]['.id']
                                    api.get_resource('/ip/hotspot/user').set(
                                        **{'.id': user_id, 'limit-uptime': mikrotik_uptime, 'comment': f'Activated via M-Pesa for {wifi_duration}'}
                                    )
                                    print(f"Activated/Updated Mikrotik Hotspot user '{hotspot_username}' with uptime limit: {mikrotik_uptime}")
                                    # To ensure immediate re-login if they were active and expired,
                                    # you might need to remove them from /ip hotspot active
                                    # or rely on the hotspot's re-login mechanism.
                                    # For a simple time limit, setting limit-uptime is usually enough.
                                else:
                                    # User does not exist, create new user
                                    api.get_resource('/ip/hotspot/user').add(
                                        name=hotspot_username,
                                        password=mpesa_phone_for_activation, # Or a generated password
                                        profile='default',
                                        **{'limit-uptime': mikrotik_uptime, 'comment': f'Created via M-Pesa for {wifi_duration}'}
                                    )
                                    print(f"Created Mikrotik Hotspot user '{hotspot_username}' with uptime limit: {mikrotik_uptime} on callback.")
                                
                                connection.disconnect()

                            except Exception as e:
                                print(f"Error activating Mikrotik Hotspot user in callback: {e}")
                        else:
                            print("Error: Could not connect to Mikrotik router for activation.")
                    else:
                        print("Error: Missing wifi_duration or phone number for Mikrotik activation in callback.")
                else:
                    print("M-Pesa Transaction Failed or Cancelled.")
            else:
                print("Unexpected callback structure or missing stkCallback.")
            
            return jsonify({"ResultCode": 0, "ResultDesc": "Callback received successfully"}), 200
        else:
            print("Received empty or non-JSON callback data.")
            return jsonify({"ResultCode": 1, "ResultDesc": "Invalid callback data"}), 400

    except Exception as e:
        print(f"Error processing M-Pesa callback: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"ResultCode": 1, "ResultDesc": f"Error processing callback: {str(e)}"}), 500


@app.route('/verify_voucher', methods=['POST'])
def verify_voucher():
    data = request.json
    voucher_code = data.get('voucher_code')
    
    if not voucher_code:
        return jsonify({"success": False, "message": "Voucher code is required."}), 400

    conn = sqlite3.connect("wifi_listings.db")
    cursor = conn.cursor()
    
    try:
        # Check if the voucher exists and is not used
        cursor.execute("SELECT * FROM wifi_vouchers WHERE voucher_number = ? AND is_used = 0", (voucher_code,))
        voucher = cursor.fetchone()
        
        if voucher:
            # Mark the voucher as used
            cursor.execute("UPDATE wifi_vouchers SET is_used = 1 WHERE voucher_number = ?", (voucher_code,))
            conn.commit()
            return jsonify({"success": True, "message": "Voucher activated successfully."})
        else:
            return jsonify({"success": False, "message": "Invalid or already used voucher code."})
            
    except sqlite3.Error as e:
        return jsonify({"success": False, "message": f"Database error: {e}"}), 500
    finally:
        conn.close()

# --- Run the Flask App ---
if __name__ == '__main__':
    create_transactions_table() # Ensure transactions table exists on app startup
    # Ensure your ngrok tunnel is running and forwarding to this port (e.g., `ngrok http 5000`)
    # And your CALLBACK_BASE_URL in .env matches the ngrok URL.
    app.run(debug=True) # host='0.0.0.0' is default for debug=True, port=5000 is default
