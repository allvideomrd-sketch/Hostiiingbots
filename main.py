# ============================================
# 🔧 REQUIRED PACKAGES INSTALLATION
# ============================================

import subprocess
import sys

packages_to_install = ['PyYAML', 'psutil', 'cryptography']

for package in packages_to_install:
    try:
        if package == 'PyYAML':
            import yaml
            print(f"✅ {package} already available")
        elif package == 'psutil':
            import psutil
            print(f"✅ {package} already available")
        elif package == 'cryptography':
            from cryptography.fernet import Fernet
            print(f"✅ {package} already available")
    except ImportError:
        print(f"⚠️ {package} not found! Installing...")
        subprocess.run([sys.executable, '-m', 'pip', 'install', package], 
                       capture_output=True, text=True)
        print(f"✅ {package} installed successfully")

# ============================================
# 📦 IMPORTS
# ============================================

import telebot
import os
import zipfile
import tempfile
import shutil
from telebot import types
import time
from datetime import datetime, timedelta
import psutil
import sqlite3
import json
import logging
import signal
import threading
import re
import atexit
import requests
from flask import Flask
from threading import Thread
import hashlib
import secrets
import string
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ============================================
# 📝 LOGGING CONFIGURATION
# ============================================

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

file_handler = logging.FileHandler('bot.log', encoding='utf-8')
file_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# ============================================
# 🔐 SECURE FILE SYSTEM CLASS
# ============================================

class SecureFileSystem:
    """Complete File Security System with Encryption + Password + Approval"""
    
    def __init__(self):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.secure_dir = os.path.join(self.base_dir, 'secure_files')
        self.keys_dir = os.path.join(self.base_dir, 'inf', 'keys')
        self.temp_dir = os.path.join(self.base_dir, 'temp_decrypted')
        
        # Create directories with secure permissions
        for dir_path in [self.secure_dir, self.keys_dir, self.temp_dir]:
            os.makedirs(dir_path, exist_ok=True)
            if os.name != 'nt':
                os.chmod(dir_path, 0o700)
        
        self.fernet = None
        self._init_encryption()
        self._init_database()
        self._start_cleanup_thread()
    
    def _init_encryption(self):
        """Initialize master encryption"""
        master_key_file = os.path.join(self.keys_dir, 'master.key')
        
        try:
            if os.path.exists(master_key_file):
                with open(master_key_file, 'rb') as f:
                    key = f.read()
            else:
                key = Fernet.generate_key()
                with open(master_key_file, 'wb') as f:
                    f.write(key)
                if os.name != 'nt':
                    os.chmod(master_key_file, 0o600)
            
            self.fernet = Fernet(key)
            logger.info("✅ Master encryption initialized")
        except Exception as e:
            logger.error(f"❌ Encryption init failed: {e}")
            raise
    
    def _init_database(self):
        """Initialize secure database"""
        db_path = os.path.join(self.keys_dir, 'secure_files.db')
        
        conn = sqlite3.connect(db_path, check_same_thread=False)
        c = conn.cursor()
        
        # Main secure files table
        c.execute('''CREATE TABLE IF NOT EXISTS secure_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            file_name TEXT,
            file_type TEXT,
            encrypted_file_path TEXT,
            file_size INTEGER,
            password_hash TEXT,
            password_salt TEXT,
            is_approved INTEGER DEFAULT 0,
            approved_by INTEGER,
            approved_at TEXT,
            uploaded_at TEXT,
            expires_at TEXT,
            max_attempts INTEGER DEFAULT 3,
            attempts_used INTEGER DEFAULT 0,
            is_locked INTEGER DEFAULT 0,
            is_deleted INTEGER DEFAULT 0,
            UNIQUE(user_id, file_name)
        )''')
        
        # Access logs
        c.execute('''CREATE TABLE IF NOT EXISTS access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            file_name TEXT,
            access_time TEXT,
            success INTEGER,
            details TEXT
        )''')
        
        # Approval requests
        c.execute('''CREATE TABLE IF NOT EXISTS approval_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            file_name TEXT,
            request_time TEXT,
            status TEXT DEFAULT 'pending',
            admin_id INTEGER,
            admin_note TEXT,
            processed_at TEXT
        )''')
        
        # User file keys
        c.execute('''CREATE TABLE IF NOT EXISTS user_file_keys (
            user_id INTEGER,
            file_name TEXT,
            file_key TEXT,
            PRIMARY KEY(user_id, file_name)
        )''')
        
        conn.commit()
        conn.close()
        logger.info("✅ Secure database initialized")
    
    def _start_cleanup_thread(self):
        """Start background cleanup thread"""
        def cleanup_worker():
            while True:
                time.sleep(3600)  # Run every hour
                self.cleanup_temp_files()
        
        thread = threading.Thread(target=cleanup_worker, daemon=True)
        thread.start()
    
    def generate_password(self, length=12):
        """Generate strong random password"""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()"
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    def hash_password(self, password):
        """Hash password with salt"""
        salt = secrets.token_hex(16)
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000
        ).hex()
        return password_hash, salt
    
    def verify_password(self, password, stored_hash, salt):
        """Verify password"""
        computed_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000
        ).hex()
        return computed_hash == stored_hash
    
    def encrypt_file(self, file_path, user_id, file_name):
        """Encrypt file with user-specific key"""
        try:
            user_key = Fernet.generate_key()
            
            conn = sqlite3.connect(os.path.join(self.keys_dir, 'secure_files.db'))
            c = conn.cursor()
            c.execute('INSERT OR REPLACE INTO user_file_keys (user_id, file_name, file_key) VALUES (?, ?, ?)',
                     (user_id, file_name, base64.b64encode(user_key).decode()))
            conn.commit()
            conn.close()
            
            f = Fernet(user_key)
            
            with open(file_path, 'rb') as file:
                file_data = file.read()
            
            encrypted_data = f.encrypt(file_data)
            
            encrypted_path = os.path.join(self.secure_dir, f"{user_id}_{file_name}.enc")
            with open(encrypted_path, 'wb') as file:
                file.write(encrypted_data)
            
            file_size = os.path.getsize(encrypted_path)
            os.remove(file_path)
            
            logger.info(f"✅ File encrypted: {file_name} for user {user_id}")
            return encrypted_path, file_size
            
        except Exception as e:
            logger.error(f"❌ Encryption failed: {e}")
            return None, 0
    
    def decrypt_file(self, user_id, file_name):
        """Decrypt file for access"""
        try:
            conn = sqlite3.connect(os.path.join(self.keys_dir, 'secure_files.db'))
            c = conn.cursor()
            c.execute('SELECT file_key FROM user_file_keys WHERE user_id = ? AND file_name = ?',
                     (user_id, file_name))
            result = c.fetchone()
            conn.close()
            
            if not result:
                logger.error(f"❌ No key found for {file_name}")
                return None
            
            user_key = base64.b64decode(result[0])
            f = Fernet(user_key)
            
            encrypted_path = os.path.join(self.secure_dir, f"{user_id}_{file_name}.enc")
            if not os.path.exists(encrypted_path):
                logger.error(f"❌ Encrypted file not found: {encrypted_path}")
                return None
            
            with open(encrypted_path, 'rb') as file:
                encrypted_data = file.read()
            
            decrypted_data = f.decrypt(encrypted_data)
            
            temp_path = os.path.join(self.temp_dir, f"{user_id}_{file_name}")
            with open(temp_path, 'wb') as file:
                file.write(decrypted_data)
            
            logger.info(f"✅ File decrypted: {file_name} for user {user_id}")
            return temp_path
            
        except Exception as e:
            logger.error(f"❌ Decryption failed: {e}")
            return None
    
    def save_file_secure(self, user_id, file_name, file_type, file_path, password=None):
        """Save file with full security"""
        try:
            encrypted_path, file_size = self.encrypt_file(file_path, user_id, file_name)
            if not encrypted_path:
                return False, "Encryption failed"
            
            password_hash = None
            password_salt = None
            if password:
                password_hash, password_salt = self.hash_password(password)
            
            expires_at = (datetime.now() + timedelta(days=30)).isoformat()
            
            conn = sqlite3.connect(os.path.join(self.keys_dir, 'secure_files.db'))
            c = conn.cursor()
            
            c.execute('''INSERT OR REPLACE INTO secure_files 
                        (user_id, file_name, file_type, encrypted_file_path, 
                         file_size, password_hash, password_salt, uploaded_at, expires_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                     (user_id, file_name, file_type, encrypted_path,
                      file_size, password_hash, password_salt, 
                      datetime.now().isoformat(), expires_at))
            
            conn.commit()
            conn.close()
            
            logger.info(f"✅ File saved securely: {file_name} for user {user_id}")
            return True, "File saved securely"
            
        except Exception as e:
            logger.error(f"❌ Save failed: {e}")
            return False, str(e)
    
    def verify_file_password(self, user_id, file_name, password):
        """Verify file password"""
        conn = sqlite3.connect(os.path.join(self.keys_dir, 'secure_files.db'))
        c = conn.cursor()
        
        try:
            c.execute('''SELECT password_hash, password_salt, attempts_used, max_attempts, is_locked 
                         FROM secure_files 
                         WHERE user_id = ? AND file_name = ? AND is_deleted = 0''',
                      (user_id, file_name))
            
            result = c.fetchone()
            if not result:
                return False, "File not found"
            
            stored_hash, salt, attempts_used, max_attempts, is_locked = result
            
            if is_locked:
                return False, "File is locked due to too many failed attempts"
            
            if not stored_hash:
                return True, "No password required"
            
            if attempts_used >= max_attempts:
                c.execute('UPDATE secure_files SET is_locked = 1 WHERE user_id = ? AND file_name = ?',
                         (user_id, file_name))
                conn.commit()
                return False, "File locked due to too many failed attempts"
            
            is_valid = self.verify_password(password, stored_hash, salt)
            
            new_attempts = attempts_used + (0 if is_valid else 1)
            c.execute('UPDATE secure_files SET attempts_used = ? WHERE user_id = ? AND file_name = ?',
                     (new_attempts, user_id, file_name))
            conn.commit()
            
            self._log_access(user_id, file_name, is_valid)
            
            if is_valid:
                c.execute('UPDATE secure_files SET attempts_used = 0 WHERE user_id = ? AND file_name = ?',
                         (user_id, file_name))
                conn.commit()
                return True, "Password verified"
            else:
                remaining = max_attempts - new_attempts
                return False, f"Incorrect password. {remaining} attempts remaining"
                
        except Exception as e:
            logger.error(f"❌ Password verification failed: {e}")
            return False, "Error verifying password"
        finally:
            conn.close()
    
    def _log_access(self, user_id, file_name, success):
        """Log file access attempt"""
        conn = sqlite3.connect(os.path.join(self.keys_dir, 'secure_files.db'))
        c = conn.cursor()
        
        try:
            c.execute('''INSERT INTO access_logs 
                        (user_id, file_name, access_time, success)
                        VALUES (?, ?, ?, ?)''',
                     (user_id, file_name, datetime.now().isoformat(), 1 if success else 0))
            conn.commit()
        except Exception as e:
            logger.error(f"❌ Log access failed: {e}")
        finally:
            conn.close()
    
    def request_approval(self, user_id, file_name):
        """Request admin approval"""
        conn = sqlite3.connect(os.path.join(self.keys_dir, 'secure_files.db'))
        c = conn.cursor()
        
        try:
            c.execute('''INSERT INTO approval_requests 
                        (user_id, file_name, request_time, status)
                        VALUES (?, ?, ?, ?)''',
                     (user_id, file_name, datetime.now().isoformat(), 'pending'))
            conn.commit()
            logger.info(f"✅ Approval requested: {file_name}")
            return True
        except Exception as e:
            logger.error(f"❌ Approval request failed: {e}")
            return False
        finally:
            conn.close()
    
    def approve_file(self, user_id, file_name, admin_id, note=None):
        """Approve file"""
        conn = sqlite3.connect(os.path.join(self.keys_dir, 'secure_files.db'))
        c = conn.cursor()
        
        try:
            c.execute('''UPDATE secure_files SET 
                        is_approved = 1, approved_by = ?, approved_at = ?
                        WHERE user_id = ? AND file_name = ?''',
                     (admin_id, datetime.now().isoformat(), user_id, file_name))
            
            c.execute('''UPDATE approval_requests SET 
                        status = 'approved', admin_id = ?, admin_note = ?, processed_at = ?
                        WHERE user_id = ? AND file_name = ? AND status = 'pending' ''',
                     (admin_id, note, datetime.now().isoformat(), user_id, file_name))
            
            conn.commit()
            logger.info(f"✅ File approved: {file_name}")
            return True
        except Exception as e:
            logger.error(f"❌ Approval failed: {e}")
            return False
        finally:
            conn.close()
    
    def reject_file(self, user_id, file_name, admin_id, reason=None):
        """Reject file"""
        conn = sqlite3.connect(os.path.join(self.keys_dir, 'secure_files.db'))
        c = conn.cursor()
        
        try:
            c.execute('''UPDATE approval_requests SET 
                        status = 'rejected', admin_id = ?, admin_note = ?, processed_at = ?
                        WHERE user_id = ? AND file_name = ? AND status = 'pending' ''',
                     (admin_id, reason, datetime.now().isoformat(), user_id, file_name))
            
            conn.commit()
            logger.info(f"❌ File rejected: {file_name}")
            return True
        except Exception as e:
            logger.error(f"❌ Rejection failed: {e}")
            return False
        finally:
            conn.close()
    
    def get_pending_approvals(self):
        """Get pending approval requests"""
        conn = sqlite3.connect(os.path.join(self.keys_dir, 'secure_files.db'))
        c = conn.cursor()
        
        try:
            c.execute('''SELECT id, user_id, file_name, request_time 
                        FROM approval_requests 
                        WHERE status = 'pending'
                        ORDER BY request_time ASC''')
            return c.fetchall()
        except Exception as e:
            logger.error(f"❌ Get pending failed: {e}")
            return []
        finally:
            conn.close()
    
    def is_file_approved(self, user_id, file_name):
        """Check if file is approved"""
        conn = sqlite3.connect(os.path.join(self.keys_dir, 'secure_files.db'))
        c = conn.cursor()
        
        try:
            c.execute('SELECT is_approved FROM secure_files WHERE user_id = ? AND file_name = ? AND is_deleted = 0',
                     (user_id, file_name))
            result = c.fetchone()
            return result and result[0] == 1
        except Exception as e:
            logger.error(f"❌ Check approval failed: {e}")
            return False
        finally:
            conn.close()
    
    def is_file_protected(self, user_id, file_name):
        """Check if file is password protected"""
        conn = sqlite3.connect(os.path.join(self.keys_dir, 'secure_files.db'))
        c = conn.cursor()
        
        try:
            c.execute('SELECT password_hash FROM secure_files WHERE user_id = ? AND file_name = ? AND is_deleted = 0',
                     (user_id, file_name))
            result = c.fetchone()
            return result and result[0] is not None
        except Exception as e:
            logger.error(f"❌ Check protection failed: {e}")
            return False
        finally:
            conn.close()
    
    def delete_file_secure(self, user_id, file_name):
        """Securely delete file"""
        conn = sqlite3.connect(os.path.join(self.keys_dir, 'secure_files.db'))
        c = conn.cursor()
        
        try:
            c.execute('SELECT encrypted_file_path FROM secure_files WHERE user_id = ? AND file_name = ?',
                     (user_id, file_name))
            result = c.fetchone()
            
            if result and os.path.exists(result[0]):
                self._secure_delete(result[0])
            
            c.execute('UPDATE secure_files SET is_deleted = 1 WHERE user_id = ? AND file_name = ?',
                     (user_id, file_name))
            
            c.execute('DELETE FROM user_file_keys WHERE user_id = ? AND file_name = ?',
                     (user_id, file_name))
            
            conn.commit()
            logger.info(f"✅ File deleted securely: {file_name}")
            return True
        except Exception as e:
            logger.error(f"❌ Delete failed: {e}")
            return False
        finally:
            conn.close()
    
    def _secure_delete(self, file_path):
        """Securely delete file with overwrite"""
        try:
            if os.path.exists(file_path):
                with open(file_path, 'rb+') as f:
                    f.write(os.urandom(os.path.getsize(file_path)))
                os.remove(file_path)
                return True
        except Exception as e:
            logger.error(f"❌ Secure delete failed: {e}")
            return False
    
    def cleanup_temp_files(self):
        """Clean up temporary files"""
        try:
            for file in os.listdir(self.temp_dir):
                file_path = os.path.join(self.temp_dir, file)
                if os.path.isfile(file_path):
                    if time.time() - os.path.getmtime(file_path) > 3600:
                        self._secure_delete(file_path)
        except Exception as e:
            logger.error(f"❌ Cleanup failed: {e}")

# ============================================
# 🚀 INITIALIZE SECURE SYSTEM
# ============================================

secure_fs = SecureFileSystem()

# ============================================
# 🤖 BOT CONFIGURATION & CONSTANTS
# ============================================

TOKEN = '8941363938:AAEVaQ_tsW6_1-zzjMVNjqRxERA4zwEizX8'
OWNER_ID = 8542876714
ADMIN_ID = 8542876714
YOUR_USERNAME = 'NullQor'
UPDATE_CHANNEL = 'https://t.me/Alphaa6m'

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_BOTS_DIR = os.path.join(BASE_DIR, 'upload_bots')
IROTECH_DIR = os.path.join(BASE_DIR, 'inf')
DATABASE_PATH = os.path.join(IROTECH_DIR, 'bot_data.db')

FREE_USER_LIMIT = 3
SUBSCRIBED_USER_LIMIT = 15
ADMIN_LIMIT = 999
OWNER_LIMIT = float('inf')

os.makedirs(UPLOAD_BOTS_DIR, exist_ok=True)
os.makedirs(IROTECH_DIR, exist_ok=True)

bot = telebot.TeleBot(TOKEN)
app = Flask('')

@app.route('/')
def home():
    return "🤖 Secure File Host Bot is Running!"

# Global variables
bot_scripts = {}
user_subscriptions = {}
user_files = {}
active_users = set()
admin_ids = {6255440067, ADMIN_ID, OWNER_ID}
bot_locked = False

# Helper Functions
def get_user_file_limit(user_id):
    if user_id == OWNER_ID:
        return OWNER_LIMIT
    if user_id in admin_ids:
        return ADMIN_LIMIT
    if user_id in user_subscriptions:
        return SUBSCRIBED_USER_LIMIT
    return FREE_USER_LIMIT

def get_user_file_count(user_id):
    return len(user_files.get(user_id, []))

def is_bot_running(user_id, file_name):
    key = f"{user_id}_{file_name}"
    return key in bot_scripts and bot_scripts[key].poll() is None

def is_password_strong(password):
    """Check password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not any(c.isupper() for c in password):
        return False, "Password must contain uppercase letter"
    if not any(c.islower() for c in password):
        return False, "Password must contain lowercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain digit"
    if not any(c in "!@#$%^&*()" for c in password):
        return False, "Password must contain special character"
    return True, "Strong password"

# ============================================
# 📊 DATABASE INITIALIZATION
# ============================================

def init_db():
    logger.info(f"Initializing database at: {DATABASE_PATH}")
    try:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()
        
        c.execute('''CREATE TABLE IF NOT EXISTS subscriptions
                     (user_id INTEGER PRIMARY KEY, expiry TEXT)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS active_users
                     (user_id INTEGER PRIMARY KEY)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS admins
                     (user_id INTEGER PRIMARY KEY)''')
        
        c.execute('INSERT OR IGNORE INTO admins (user_id) VALUES (?)', (OWNER_ID,))
        if ADMIN_ID != OWNER_ID:
            c.execute('INSERT OR IGNORE INTO admins (user_id) VALUES (?)', (ADMIN_ID,))
        
        conn.commit()
        conn.close()
        logger.info("✅ Database initialized")
    except Exception as e:
        logger.error(f"❌ Database init error: {e}")

init_db()

# ============================================
# 📤 FILE UPLOAD HANDLER
# ============================================

@bot.message_handler(content_types=['document'])
def handle_file_upload(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    doc = message.document
    
    if bot_locked and user_id not in admin_ids:
        bot.reply_to(message, "⚠️ Bot locked by admin.")
        return
    
    file_limit = get_user_file_limit(user_id)
    current_files = get_user_file_count(user_id)
    if current_files >= file_limit:
        bot.reply_to(message, f"⚠️ File limit reached ({current_files}/{file_limit}). Delete files first.")
        return
    
    file_name = doc.file_name
    if not file_name:
        bot.reply_to(message, "⚠️ No file name.")
        return
    
    file_ext = os.path.splitext(file_name)[1].lower()
    allowed_extensions = ['.py', '.js', '.zip', '.txt', '.json', '.yml', '.yaml']
    if file_ext not in allowed_extensions:
        bot.reply_to(message, f"⚠️ Unsupported file type. Allowed: {', '.join(allowed_extensions)}")
        return
    
    max_file_size = 20 * 1024 * 1024
    if doc.file_size > max_file_size:
        bot.reply_to(message, f"⚠️ File too large (Max: {max_file_size // 1024 // 1024} MB)")
        return
    
    try:
        try:
            bot.forward_message(OWNER_ID, chat_id, message.message_id)
            bot.send_message(OWNER_ID, 
                f"📥 *New File Upload*\n"
                f"👤 User: {message.from_user.first_name} (@{message.from_user.username or 'N/A'})\n"
                f"🆔 ID: `{user_id}`\n"
                f"📁 File: `{file_name}`\n"
                f"📏 Size: {doc.file_size // 1024} KB\n"
                f"📅 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                parse_mode='Markdown')
        except Exception as e:
            logger.error(f"Failed to forward to owner: {e}")
        
        status_msg = bot.reply_to(message, f"⏳ Downloading `{file_name}`...")
        file_info = bot.get_file(doc.file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        
        temp_path = os.path.join(UPLOAD_BOTS_DIR, f"temp_{user_id}_{file_name}")
        with open(temp_path, 'wb') as f:
            f.write(downloaded_file)
        
        bot.edit_message_text(
            f"📁 File `{file_name}` downloaded!\n\n"
            "🔐 *Set Password Protection*\n"
            "Type a password for this file (min 8 chars, with uppercase, lowercase, digit, special char)\n"
            "Or type `skip` to upload without password",
            chat_id, status_msg.message_id, parse_mode='Markdown')
        
        bot.register_next_step_handler(message, process_file_password_setup, 
                                      user_id, file_name, file_ext, temp_path, status_msg)
        
    except Exception as e:
        logger.error(f"❌ Upload error: {e}")
        bot.reply_to(message, f"❌ Upload failed: {str(e)}")

def process_file_password_setup(message, user_id, file_name, file_ext, temp_path, status_msg):
    password = message.text.strip()
    
    if password.lower() == 'skip':
        password = None
        bot.edit_message_text("⏳ Saving file without password...", 
                            message.chat.id, status_msg.message_id)
    else:
        is_strong, msg = is_password_strong(password)
        if not is_strong:
            bot.edit_message_text(
                f"⚠️ {msg}\n\nPlease try again or type `skip` to upload without password",
                message.chat.id, status_msg.message_id, parse_mode='Markdown')
            bot.register_next_step_handler(message, process_file_password_setup, 
                                          user_id, file_name, file_ext, temp_path, status_msg)
            return
        bot.edit_message_text("⏳ Saving file with password protection...", 
                            message.chat.id, status_msg.message_id)
    
    file_type = file_ext[1:]
    success, msg = secure_fs.save_file_secure(user_id, file_name, file_type, temp_path, password)
    
    if not success:
        bot.edit_message_text(f"❌ Failed to save: {msg}", 
                            message.chat.id, status_msg.message_id)
        return
    
    secure_fs.request_approval(user_id, file_name)
    
    if user_id not in user_files:
        user_files[user_id] = []
    user_files[user_id].append((file_name, file_type))
    
    admin_notification = (
        f"🔐 *New File Needs Approval*\n\n"
        f"👤 User: {user_id}\n"
        f"📁 File: `{file_name}`\n"
        f"🔒 Password: {'Yes' if password else 'No'}\n"
        f"📅 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        f"Use /approvals to review"
    )
    
    for admin_id in admin_ids:
        try:
            bot.send_message(admin_id, admin_notification, parse_mode='Markdown')
        except:
            pass
    
    if password:
        bot.edit_message_text(
            f"✅ File `{file_name}` uploaded securely!\n\n"
            f"🔐 Password: `{password}`\n"
            f"⚠️ Save this password! You need it to run this file.\n"
            f"⏳ Waiting for admin approval...\n"
            f"You'll be notified when approved.",
            message.chat.id, status_msg.message_id, parse_mode='Markdown')
    else:
        bot.edit_message_text(
            f"✅ File `{file_name}` uploaded!\n"
            f"⏳ Waiting for admin approval...\n"
            f"You'll be notified when approved.",
            message.chat.id, status_msg.message_id, parse_mode='Markdown')

# ============================================
# 👑 ADMIN APPROVAL SYSTEM
# ============================================

@bot.message_handler(commands=['approvals'])
def show_approvals(message):
    if message.from_user.id not in admin_ids:
        bot.reply_to(message, "⚠️ Admin only!")
        return
    
    pending = secure_fs.get_pending_approvals()
    
    if not pending:
        bot.reply_to(message, "✅ No pending approvals.")
        return
    
    markup = types.InlineKeyboardMarkup(row_width=2)
    
    for req_id, user_id, file_name, request_time in pending:
        btn_text = f"📁 {file_name} (User: {user_id})"
        markup.add(types.InlineKeyboardButton(
            btn_text, 
            callback_data=f'approve_{req_id}_{user_id}_{file_name}'
        ))
    
    bot.reply_to(message, 
        f"📋 *Pending Approvals: {len(pending)}*\n\n"
        "Click on a file to approve or reject.",
        reply_markup=markup, parse_mode='Markdown')

@bot.callback_query_handler(func=lambda call: call.data.startswith('approve_'))
def handle_approval(call):
    if call.from_user.id not in admin_ids:
        bot.answer_callback_query(call.id, "⚠️ Admin only!", show_alert=True)
        return
    
    parts = call.data.split('_')
    req_id = int(parts[1])
    user_id = int(parts[2])
    file_name = '_'.join(parts[3:])
    
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.row(
        types.InlineKeyboardButton("✅ Approve", callback_data=f'approve_yes_{req_id}_{user_id}_{file_name}'),
        types.InlineKeyboardButton("❌ Reject", callback_data=f'approve_no_{req_id}_{user_id}_{file_name}')
    )
    
    bot.edit_message_text(
        f"📁 *File: {file_name}*\n"
        f"👤 User: {user_id}\n\n"
        f"Choose action:",
        call.message.chat.id, call.message.message_id,
        reply_markup=markup, parse_mode='Markdown')
    
    bot.answer_callback_query(call.id)

@bot.callback_query_handler(func=lambda call: call.data.startswith('approve_yes_'))
def approve_file_callback(call):
    if call.from_user.id not in admin_ids:
        bot.answer_callback_query(call.id, "⚠️ Admin only!", show_alert=True)
        return
    
    parts = call.data.split('_')
    req_id = int(parts[2])
    user_id = int(parts[3])
    file_name = '_'.join(parts[4:])
    
    secure_fs.approve_file(user_id, file_name, call.from_user.id, "Approved by admin")
    
    try:
        bot.send_message(user_id, 
            f"✅ Your file `{file_name}` has been *APPROVED*!\n"
            f"You can now run it using /checkfiles",
            parse_mode='Markdown')
    except:
        pass
    
    bot.edit_message_text(
        f"✅ File `{file_name}` approved!\n"
        f"User {user_id} has been notified.",
        call.message.chat.id, call.message.message_id)
    
    bot.answer_callback_query(call.id, "✅ File approved!")

@bot.callback_query_handler(func=lambda call: call.data.startswith('approve_no_'))
def reject_file_callback(call):
    if call.from_user.id not in admin_ids:
        bot.answer_callback_query(call.id, "⚠️ Admin only!", show_alert=True)
        return
    
    parts = call.data.split('_')
    req_id = int(parts[2])
    user_id = int(parts[3])
    file_name = '_'.join(parts[4:])
    
    secure_fs.reject_file(user_id, file_name, call.from_user.id, "Rejected by admin")
    
    try:
        bot.send_message(user_id, 
            f"❌ Your file `{file_name}` has been *REJECTED*.\n"
            f"Contact admin for details.",
            parse_mode='Markdown')
    except:
        pass
    
    bot.edit_message_text(
        f"❌ File `{file_name}` rejected.\n"
        f"User {user_id} has been notified.",
        call.message.chat.id, call.message.message_id)
    
    bot.answer_callback_query(call.id, "❌ File rejected!")

# ============================================
# 📂 CHECK FILES & CONTROL SYSTEM
# ============================================

@bot.callback_query_handler(func=lambda call: call.data.startswith('file_'))
def file_control_callback(call):
    try:
        _, user_id_str, file_name = call.data.split('_', 2)
        user_id = int(user_id_str)
        requesting_user_id = call.from_user.id
        
        if requesting_user_id != user_id and requesting_user_id not in admin_ids:
            bot.answer_callback_query(call.id, "⚠️ You can only manage your own files!", show_alert=True)
            return
        
        if not secure_fs.is_file_approved(user_id, file_name):
            if requesting_user_id in admin_ids:
                bot.answer_callback_query(call.id, "⚠️ File not approved yet!", show_alert=True)
                return
            else:
                bot.answer_callback_query(call.id, "⏳ File waiting for approval!", show_alert=True)
                return
        
        is_protected = secure_fs.is_file_protected(user_id, file_name)
        
        if is_protected and requesting_user_id not in admin_ids:
            msg = bot.send_message(call.message.chat.id,
                f"🔐 File `{file_name}` is password protected!\n\n"
                "Send the password to access this file.",
                parse_mode='Markdown')
            bot.register_next_step_handler(msg, process_file_password, user_id, file_name, call)
            bot.answer_callback_query(call.id)
            return
        
        show_file_controls(call, user_id, file_name)
        
    except Exception as e:
        logger.error(f"❌ File control error: {e}")
        bot.answer_callback_query(call.id, "Error loading file.", show_alert=True)

def process_file_password(message, user_id, file_name, original_call):
    password = message.text.strip()
    is_valid, msg = secure_fs.verify_file_password(user_id, file_name, password)
    
    if is_valid:
        bot.reply_to(message, f"✅ Password correct! Accessing `{file_name}`...", parse_mode='Markdown')
        show_file_controls(original_call, user_id, file_name)
    else:
        bot.reply_to(message, f"❌ {msg}\n\nTry again or /cancel")
        msg = bot.send_message(message.chat.id, f"🔐 Enter password for `{file_name}`:", parse_mode='Markdown')
        bot.register_next_step_handler(msg, process_file_password, user_id, file_name, original_call)

def show_file_controls(call, user_id, file_name):
    is_running = is_bot_running(user_id, file_name)
    markup = types.InlineKeyboardMarkup(row_width=2)
    
    if is_running:
        markup.row(
            types.InlineKeyboardButton("🔴 Stop", callback_data=f'stop_{user_id}_{file_name}'),
            types.InlineKeyboardButton("🔄 Restart", callback_data=f'restart_{user_id}_{file_name}')
        )
    else:
        markup.row(
            types.InlineKeyboardButton("🟢 Start", callback_data=f'start_{user_id}_{file_name}')
        )
    
    markup.row(
        types.InlineKeyboardButton("📜 Logs", callback_data=f'logs_{user_id}_{file_name}'),
        types.InlineKeyboardButton("🗑️ Delete", callback_data=f'delete_{user_id}_{file_name}')
    )
    
    if call.from_user.id in admin_ids:
        markup.row(
            types.InlineKeyboardButton("🔐 Set Password", callback_data=f'setpass_{user_id}_{file_name}'),
            types.InlineKeyboardButton("🔑 Show Password", callback_data=f'showpass_{user_id}_{file_name}')
        )
    
    markup.row(types.InlineKeyboardButton("🔙 Back to Files", callback_data='check_files'))
    
    status_text = '🟢 Running' if is_running else '🔴 Stopped'
    is_approved = secure_fs.is_file_approved(user_id, file_name)
    is_protected = secure_fs.is_file_protected(user_id, file_name)
    
    bot.edit_message_text(
        f"⚙️ *File: {file_name}*\n"
        f"Status: {status_text}\n"
        f"🔒 Protected: {'Yes' if is_protected else 'No'}\n"
        f"✅ Approved: {'Yes' if is_approved else 'No'}\n"
        f"👤 Owner: {user_id}",
        call.message.chat.id, call.message.message_id,
        reply_markup=markup, parse_mode='Markdown')

# ============================================
# 🔐 PASSWORD MANAGEMENT - ADMIN ONLY
# ============================================

@bot.callback_query_handler(func=lambda call: call.data.startswith('setpass_'))
def set_password_callback(call):
    if call.from_user.id not in admin_ids:
        bot.answer_callback_query(call.id, "⚠️ Admin only!", show_alert=True)
        return
    
    parts = call.data.split('_')
    user_id = int(parts[1])
    file_name = '_'.join(parts[2:])
    
    msg = bot.send_message(call.message.chat.id,
        f"🔐 Set password for `{file_name}`\n\n"
        "Send new password (min 8 chars with uppercase, lowercase, digit, special char)",
        parse_mode='Markdown')
    
    bot.register_next_step_handler(msg, process_set_password, user_id, file_name, call)

def process_set_password(message, user_id, file_name, call):
    password = message.text.strip()
    is_strong, msg = is_password_strong(password)
    if not is_strong:
        bot.reply_to(message, f"⚠️ {msg}\nTry again.")
        return
    
    password_hash, salt = secure_fs.hash_password(password)
    
    conn = sqlite3.connect(os.path.join(secure_fs.keys_dir, 'secure_files.db'))
    c = conn.cursor()
    c.execute('''UPDATE secure_files 
                SET password_hash = ?, password_salt = ?, max_attempts = 3, attempts_used = 0, is_locked = 0
                WHERE user_id = ? AND file_name = ?''',
             (password_hash, salt, user_id, file_name))
    conn.commit()
    conn.close()
    
    bot.reply_to(message, f"✅ Password set for `{file_name}`!\n🔑 Password: `{password}`", parse_mode='Markdown')
    
    try:
        bot.send_message(user_id, f"🔐 Admin set a password for your file `{file_name}`.\nContact admin for the password.")
    except:
        pass

@bot.callback_query_handler(func=lambda call: call.data.startswith('showpass_'))
def show_password_callback(call):
    if call.from_user.id not in admin_ids:
        bot.answer_callback_query(call.id, "⚠️ Admin only!", show_alert=True)
        return
    
    parts = call.data.split('_')
    user_id = int(parts[1])
    file_name = '_'.join(parts[2:])
    
    conn = sqlite3.connect(os.path.join(secure_fs.keys_dir, 'secure_files.db'))
    c = conn.cursor()
    c.execute('SELECT password_hash FROM secure_files WHERE user_id = ? AND file_name = ?',
             (user_id, file_name))
    result = c.fetchone()
    conn.close()
    
    if result and result[0]:
        new_password = secure_fs.generate_password()
        password_hash, salt = secure_fs.hash_password(new_password)
        
        conn = sqlite3.connect(os.path.join(secure_fs.keys_dir, 'secure_files.db'))
        c = conn.cursor()
        c.execute('UPDATE secure_files SET password_hash = ?, password_salt = ? WHERE user_id = ? AND file_name = ?',
                 (password_hash, salt, user_id, file_name))
        conn.commit()
        conn.close()
        
        bot.answer_callback_query(call.id, f"🔑 New password generated: {new_password}", show_alert=True)
        bot.send_message(call.message.chat.id,
            f"🔑 New password for `{file_name}`: `{new_password}`\n"
            f"Share this with the user securely.",
            parse_mode='Markdown')
        
        try:
            bot.send_message(user_id, f"🔑 Your password for `{file_name}` has been reset by admin.\nContact admin for the new password.")
        except:
            pass
    else:
        bot.answer_callback_query(call.id, "❌ No password set for this file!", show_alert=True)

# ============================================
# 🚀 START SERVER & BOT
# ============================================

def keep_alive():
    """Keep bot alive with Flask"""
    def run():
        port = int(os.environ.get("PORT", 8178))
        app.run(host='0.0.0.0', port=port)
    
    t = Thread(target=run)
    t.daemon = True
    t.start()
    print("✅ Flask keep-alive server started.")

def cleanup():
    """Cleanup on shutdown"""
    logger.warning("Shutting down...")
    secure_fs.cleanup_temp_files()
    logger.info("Cleanup complete")

atexit.register(cleanup)

if __name__ == '__main__':
    logger.info("="*50)
    logger.info("🤖 Secure File Host Bot Starting...")
    logger.info(f"🔑 Owner ID: {OWNER_ID}")
    logger.info(f"🛡️ Admin IDs: {admin_ids}")
    logger.info("="*50)
    
    keep_alive()
    
    while True:
        try:
            bot.infinity_polling(logger_level=logging.INFO, timeout=60)
        except Exception as e:
            logger.error(f"❌ Bot error: {e}")
            time.sleep(10)
