import sqlite3
import os
from cryptography.fernet import Fernet
import base64
import hashlib
from typing import List, Dict, Optional


class PasswordVaultDB:
    def __init__(self, db_path: str = "password_vault.db"):
        self.db_path = db_path
        self.fernet = None
        self._init_db()

    def _init_db(self):
        """Initialize database and create tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Create passwords table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                website TEXT NOT NULL,
                username TEXT NOT NULL,
                encrypted_password TEXT NOT NULL,
                category TEXT DEFAULT 'General',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Create master key table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS master_key (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                key_hash TEXT NOT NULL,
                salt TEXT NOT NULL
            )
        ''')

        conn.commit()
        conn.close()

    def setup_master_key(self, master_password: str) -> bool:
        """Set up master password for encryption"""
        try:
            salt = os.urandom(32)
            key_hash = hashlib.pbkdf2_hmac(
                'sha256',
                master_password.encode(),
                salt,
                100000
            )

            # Generate encryption key from master password
            key = hashlib.pbkdf2_hmac(
                'sha256',
                master_password.encode(),
                salt,
                100000,
                32
            )
            fernet_key = base64.urlsafe_b64encode(key)
            self.fernet = Fernet(fernet_key)

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT OR REPLACE INTO master_key (id, key_hash, salt)
                VALUES (1, ?, ?)
            ''', (key_hash.hex(), salt.hex()))

            conn.commit()
            conn.close()
            return True

        except Exception as e:
            print(f"Error setting up master key: {e}")
            return False

    def verify_master_key(self, master_password: str) -> bool:
        """Verify master password and initialize encryption"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('SELECT key_hash, salt FROM master_key WHERE id = 1')
            result = cursor.fetchone()
            conn.close()

            if not result:
                return False

            stored_hash_hex, salt_hex = result
            salt = bytes.fromhex(salt_hex)

            # Verify password
            computed_hash = hashlib.pbkdf2_hmac(
                'sha256',
                master_password.encode(),
                salt,
                100000
            )

            if computed_hash.hex() != stored_hash_hex:
                return False

            # Initialize encryption
            key = hashlib.pbkdf2_hmac(
                'sha256',
                master_password.encode(),
                salt,
                100000,
                32
            )
            fernet_key = base64.urlsafe_b64encode(key)
            self.fernet = Fernet(fernet_key)
            return True

        except Exception as e:
            print(f"Error verifying master key: {e}")
            return False

    def add_password(self, website: str, username: str, password: str, category: str = "General") -> bool:
        """Add a new password entry"""
        if not self.fernet:
            raise Exception("Master key not initialized")

        try:
            encrypted_password = self.fernet.encrypt(password.encode()).decode()

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO passwords (website, username, encrypted_password, category)
                VALUES (?, ?, ?, ?)
            ''', (website, username, encrypted_password, category))

            conn.commit()
            conn.close()
            return True

        except Exception as e:
            print(f"Error adding password: {e}")
            return False

    def get_password(self, entry_id: int) -> Optional[Dict]:
        """Retrieve a password entry by ID"""
        if not self.fernet:
            raise Exception("Master key not initialized")

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT id, website, username, encrypted_password, category 
                FROM passwords WHERE id = ?
            ''', (entry_id,))

            result = cursor.fetchone()
            conn.close()

            if result:
                id, website, username, encrypted_password, category = result
                decrypted_password = self.fernet.decrypt(encrypted_password.encode()).decode()

                return {
                    'id': id,
                    'website': website,
                    'username': username,
                    'password': decrypted_password,
                    'category': category
                }
            return None

        except Exception as e:
            print(f"Error retrieving password: {e}")
            return None

    def get_all_passwords(self) -> List[Dict]:
        """Retrieve all password entries"""
        if not self.fernet:
            raise Exception("Master key not initialized")

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT id, website, username, encrypted_password, category 
                FROM passwords ORDER BY website
            ''')

            results = cursor.fetchall()
            conn.close()

            entries = []
            for result in results:
                id, website, username, encrypted_password, category = result
                decrypted_password = self.fernet.decrypt(encrypted_password.encode()).decode()

                entries.append({
                    'id': id,
                    'website': website,
                    'username': username,
                    'password': decrypted_password,
                    'category': category
                })

            return entries

        except Exception as e:
            print(f"Error retrieving passwords: {e}")
            return []

    def search_passwords(self, query: str) -> List[Dict]:
        """Search passwords by website, username, or category"""
        if not self.fernet:
            raise Exception("Master key not initialized")

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT id, website, username, encrypted_password, category 
                FROM passwords 
                WHERE website LIKE ? OR username LIKE ? OR category LIKE ?
                ORDER BY website
            ''', (f'%{query}%', f'%{query}%', f'%{query}%'))

            results = cursor.fetchall()
            conn.close()

            entries = []
            for result in results:
                id, website, username, encrypted_password, category = result
                decrypted_password = self.fernet.decrypt(encrypted_password.encode()).decode()

                entries.append({
                    'id': id,
                    'website': website,
                    'username': username,
                    'password': decrypted_password,
                    'category': category
                })

            return entries

        except Exception as e:
            print(f"Error searching passwords: {e}")
            return []

    def update_password(self, entry_id: int, website: str, username: str, password: str, category: str) -> bool:
        """Update a password entry"""
        if not self.fernet:
            raise Exception("Master key not initialized")

        try:
            encrypted_password = self.fernet.encrypt(password.encode()).decode()

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                UPDATE passwords 
                SET website = ?, username = ?, encrypted_password = ?, category = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (website, username, encrypted_password, category, entry_id))

            conn.commit()
            conn.close()
            return cursor.rowcount > 0

        except Exception as e:
            print(f"Error updating password: {e}")
            return False

    def delete_password(self, entry_id: int) -> bool:
        """Delete a password entry"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('DELETE FROM passwords WHERE id = ?', (entry_id,))

            conn.commit()
            conn.close()
            return cursor.rowcount > 0

        except Exception as e:
            print(f"Error deleting password: {e}")
            return False

    def get_categories(self) -> List[str]:
        """Get all unique categories"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('SELECT DISTINCT category FROM passwords ORDER BY category')
            results = cursor.fetchall()
            conn.close()

            return [result[0] for result in results]

        except Exception as e:
            print(f"Error getting categories: {e}")
            return []
