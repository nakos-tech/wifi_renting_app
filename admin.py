import sqlite3
import random
import string
import logging 
import secrets
from functools import wraps
from flask import Blueprint, render_template, request, jsonify, session, g, redirect, url_for
from flask_wtf.csrf import CSRFProtect

# Define the Blueprint for the admin routes
admin_bp = Blueprint('admin_bp', __name__, template_folder='templates')

# Define database file paths
DATABASE_WIFI = 'wifi_listings.db'
DATABASE_MEMBERS = 'members.db'

# === Database Connection Functions ===
def get_db_wifi():
    db = getattr(g, '_database_wifi', None)
    if db is None:
        db = g._database_wifi = sqlite3.connect(DATABASE_WIFI)
        db.row_factory = sqlite3.Row  
        create_tables_wifi(db)
    return db

def get_db_members():
    db = getattr(g, '_database_members', None)
    if db is None:
        db = g._database_members = sqlite3.connect(DATABASE_MEMBERS)
        db.row_factory = sqlite3.Row
        create_tables_members(db)
    return db

def create_tables_wifi(db):
    cursor = db.cursor()
    # Corrected column name to wifi_duration to match your database
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS wifi_listings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            wifi_duration TEXT NOT NULL UNIQUE,
            amount REAL NOT NULL,
            max_devices INTEGER
        );
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS wifi_vouchers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            voucher_code TEXT NOT NULL UNIQUE,
            plan_duration TEXT NOT NULL,
            plan_amount REAL NOT NULL,
            is_used INTEGER DEFAULT 0,
            generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    db.commit()

def create_tables_members(db):
    cursor = db.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT,
            phone TEXT,
            is_active INTEGER DEFAULT 0
        );
    """)
    db.commit()

@admin_bp.teardown_app_request
def close_connection(exception):
    db_wifi = getattr(g, '_database_wifi', None)
    if db_wifi is not None:
        db_wifi.close()
    db_members = getattr(g, '_database_members', None)
    if db_members is not None:
        db_members.close()

# === Utility Functions ===
def is_admin():
    return 'username' in session and session.get('is_admin') == 1

def generate_unique_voucher_code(cursor):
    """Generates a unique voucher code."""
    while True:
        voucher_code = secrets.token_hex(6).upper()
        cursor.execute("SELECT 1 FROM wifi_vouchers WHERE voucher_number = ?", (voucher_code,))
        if cursor.fetchone() is None:
            return voucher_code

# === Admin Routes ===
@admin_bp.route('/admin_panel')
def admin_panel():
    # Example: Check for admin status
    # if not is_admin():
    #     return redirect(url_for('auth_bp.login'))

    db_wifi = get_db_wifi()
    cursor_wifi = db_wifi.cursor()
    db_members = get_db_members()
    cursor_members = db_members.cursor()
    
    # Get wifi plans
    cursor_wifi.execute("SELECT * FROM wifi_listings")
    wifi_plans = cursor_wifi.fetchall()

    # Get users for display
    users = []
    try:
        cursor_members.execute("SELECT * FROM users")
        raw_users = cursor_members.fetchall()
        for user in raw_users:
            users.append({
                'username': user['username'],
                'email': user['email'],
                'phone': user['phone']
                # 'is_active': user['is_active']
            })
    except sqlite3.OperationalError as e:
        logging.error(f"Error fetching users: {e}")
        users = [] 
    
    # Get vouchers for display
    cursor_wifi.execute("SELECT * FROM wifi_vouchers")
    wifi_vouchers = cursor_wifi.fetchall()

    return render_template('admin_panel.html', wifi_plans=wifi_plans, users=users, wifi_vouchers=wifi_vouchers)

@admin_bp.route('/add_plan', methods=['POST'])
def add_plan():
    # if not is_admin():
    #     return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    # Use request.form to get data from FormData
    wifi_duration = request.form.get('wifi_duration')
    amount = request.form.get('amount')
    max_devices = request.form.get('new_devices')

    if not all([wifi_duration, amount, max_devices]):
        return jsonify({'success': False, 'message': 'Missing required fields'}), 400

    try:
        amount = float(amount)
        max_devices = int(max_devices)
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'Invalid data format for amount or devices'}), 400

    db = get_db_wifi()
    cursor = db.cursor()
    try:
        # Corrected SQL query to use 'wifi_duration'
        cursor.execute("INSERT INTO wifi_listings (wifi_duration, amount, devices) VALUES (?, ?, ?)", 
                       (wifi_duration, amount, max_devices))
        db.commit()
        return jsonify({'success': True, 'message': 'Plan added successfully!'})
    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'message': 'A plan with this duration already exists.'}), 409
    except Exception as e:
        logging.error(f"Error adding plan: {str(e)}")
        return jsonify({'success': False, 'message': f'An error occurred: {str(e)}'}), 500

@admin_bp.route('/update_plan', methods=['POST'])
def update_plan():
    # if not is_admin():
    #     return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    old_duration = request.form.get('old_duration')
    new_duration = request.form.get('new_duration')
    new_amount = request.form.get('new_amount')
    new_devices = request.form.get('new_devices')

    if not all([old_duration, new_duration, new_amount, new_devices]):
        return jsonify({'success': False, 'message': 'Missing required fields'}), 400

    try:
        new_amount = float(new_amount)
        new_devices = int(new_devices)
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'Invalid data format for amount or devices'}), 400

    db = get_db_wifi()
    cursor = db.cursor()
    try:
        # Corrected SQL query to use 'wifi_duration'
        cursor.execute("UPDATE wifi_listings SET wifi_duration = ?, amount = ?, devices = ? WHERE wifi_duration = ?", 
                       (new_duration, new_amount, new_devices, old_duration))
        db.commit()
        if cursor.rowcount == 0:
            return jsonify({'success': False, 'message': 'Plan not found.'}), 404
        return jsonify({'success': True, 'message': 'Plan updated successfully!'})
    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'message': 'A plan with the new duration already exists.'}), 409
    except Exception as e:
        logging.error(f"Error updating plan: {str(e)}")
        return jsonify({'success': False, 'message': f'An error occurred: {str(e)}'}), 500

@admin_bp.route('/delete_plan', methods=['POST'])
def delete_plan():
    # if not is_admin():
    #     return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    wifi_duration = request.form.get('wifi_duration')
    
    if not wifi_duration:
        return jsonify({'success': False, 'message': 'Missing plan duration.'}), 400

    db = get_db_wifi()
    cursor = db.cursor()
    try:
        # Corrected SQL query to use 'wifi_duration'
        cursor.execute('DELETE FROM wifi_listings WHERE wifi_duration = ?', (wifi_duration,))
        db.commit()
        if cursor.rowcount == 0:
            return jsonify({'success': False, 'message': 'Plan not found.'}), 404
        return jsonify({'success': True, 'message': f'Plan "{wifi_duration}" deleted successfully.'})
    except Exception as e:
        logging.error(f"Error deleting plan: {str(e)}")
        return jsonify({'success': False, 'message': f'Error deleting plan: {str(e)}'}), 500


@admin_bp.route('/generate_voucher', methods=['POST'])
def generate_voucher():
    # if not is_admin():
    #     return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    plan_duration = request.form.get('plan_duration')
    
    if not isinstance(plan_duration, str) or not plan_duration.strip():
        return jsonify({'success': False, 'message': 'Invalid plan duration format.'}), 400

    db = get_db_wifi()
    cursor = db.cursor()
    try:
        cursor.execute("SELECT amount FROM wifi_listings WHERE wifi_duration = ?", (plan_duration,))
        plan_data = cursor.fetchone()
        if plan_data is None:
            return jsonify({'success': False, 'message': 'Selected plan does not exist.'}), 404
            
        plan_amount = plan_data['amount']
        
        voucher_code = generate_unique_voucher_code(cursor)
        
        # Corrected INSERT statement to use 'voucher_number'
        cursor.execute(
            "INSERT INTO wifi_vouchers (voucher_number, plan_duration, plan_amount, is_used) VALUES (?, ?, ?, 0)", 
            (voucher_code, plan_duration, plan_amount)
        )
        db.commit()
        
        logging.info(f"Voucher generated: {voucher_code} for plan: {plan_duration}")
        
        return jsonify({
            'success': True, 
            'message': 'Voucher generated successfully!', 
            'voucher_code': voucher_code
        })
        
    except Exception as e:
        logging.error(f"Voucher generation error: {str(e)}")
        return jsonify({'success': False, 'message': f'An error occurred: {str(e)}'}), 500

@admin_bp.route('/get_payments')
def get_payments():
    db = get_db_wifi()
    cursor = db.cursor()

    # fetch all successful payments 
    try:
        cursor.execute("""
        
        SELECT p.id, p.plan_duration, p.amount, p.phone, p.mpesa_receipt_number, p.created_at, p.status

        FROM payments p 
        LEFT JOIN payment_vouchers pv ON pv.payment_id = p.id
        WHERE p.status = "completed"
        ORDER BY p.id
        """
        )

        rows = cursor.fetchall()
        payments = [dict(row) for row in rows]
        return jsonify({"success": True, "payments": payments})
    except Exception as e:
        logging.error(f"Error fetching payments: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500

@admin_bp.route('/get_weekly_analysis')
def get_weekly_analysis():
    db = get_db_wifi()
    cursor = db.cursor()
    try:
        start_date = request.args.get('start')
        end_date   = request.args.get('end')

        if not start_date or not end_date:
            return jsonify({'success': False, 'message': 'Missing date range'}), 400

        cursor.execute("""
            SELECT 
                DATE(transaction_date) as day,
                COUNT(*) as transactions,
                SUM(amount) as revenue
            FROM payments
            WHERE status = 'completed'
              AND DATE(transaction_date) BETWEEN ? AND ?
            GROUP BY DATE(transaction_date)
            ORDER BY day ASC
        """, (start_date, end_date))

        rows = cursor.fetchall()

        # Build a full 7-day result Mon–Sun, filling missing days with zeros
        from datetime import datetime, timedelta
        result = []
        start = datetime.strptime(start_date, '%Y-%m-%d')

        daily_map = {row['day']: row for row in rows}

        for i in range(7):
            date_str = (start + timedelta(days=i)).strftime('%Y-%m-%d')
            row = daily_map.get(date_str)
            result.append({
                'date':         date_str,
                'transactions': row['transactions'] if row else 0,
                'revenue':      float(row['revenue']) if row and row['revenue'] else 0.0
            })

        return jsonify({'success': True, 'days': result})

    except Exception as e:
        logging.error(f"Weekly analysis error: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500