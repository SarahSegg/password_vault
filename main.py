import re
import random
import string
from db_connector import PasswordVaultDB
import getpass


RE_SPECIALS = "!@#$%^&*()_+-=[]{}|;:,.<>?"


class PasswordVault:
    def __init__(self):
        self.db = PasswordVaultDB()
        self.is_authenticated = False

    def check_master_key_exists(self) -> bool:
        """Check if master key is already set up"""
        import sqlite3
        try:
            conn = sqlite3.connect(self.db.db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM master_key WHERE id = 1')
            result = cursor.fetchone()
            conn.close()
            return (result or [0])[0] > 0
        except Exception:
            # If the DB or table doesn't exist yet, treat as not set up
            return False

    def authenticate(self):
        """Handle user authentication"""
        if not self.check_master_key_exists():
            print("\n=== Welcome to Password Vault ===")
            print("Setting up your master password...")
            while True:
                master_password = getpass.getpass("Create master password: ")
                confirm_password = getpass.getpass("Confirm master password: ")

                if master_password != confirm_password:
                    print("Passwords don't match. Try again.")
                    continue

                if len(master_password) < 8:
                    print("Master password must be at least 8 characters long.")
                    continue

                if self.db.setup_master_key(master_password):
                    print("Master password set successfully!")
                    self.is_authenticated = True
                    break
                else:
                    print("Failed to set up master password. Please try again.")
        else:
            print("\n=== Password Vault Login ===")
            attempts = 3
            while attempts > 0:
                master_password = getpass.getpass("Enter master password: ")
                if self.db.verify_master_key(master_password):
                    self.is_authenticated = True
                    print("Authentication successful!")
                    break
                else:
                    attempts -= 1
                    print(f"Invalid password. {attempts} attempts remaining.")

            if not self.is_authenticated:
                print("Too many failed attempts. Exiting.")
                exit()

    def password_strength_meter(self, password: str) -> dict:
        """Check password strength"""
        score = 0
        feedback = []

        # Length check
        if len(password) >= 12:
            score += 2
        elif len(password) >= 8:
            score += 1
        else:
            feedback.append("Password should be at least 8 characters long")

        # Lowercase check
        if re.search(r'[a-z]', password):
            score += 1
        else:
            feedback.append("Add lowercase letters")

        # Uppercase check
        if re.search(r'[A-Z]', password):
            score += 1
        else:
            feedback.append("Add uppercase letters")

        # Digit check
        if re.search(r'\d', password):
            score += 1
        else:
            feedback.append("Add numbers")

        # Special character check
        if re.search(r'[!@#$%^&*(),.?\":{}|<>]', password):
            score += 1
        else:
            feedback.append("Add special characters")

        # Determine strength level
        if score >= 5:
            strength = "Very Strong"
        elif score >= 4:
            strength = "Strong"
        elif score >= 3:
            strength = "Moderate"
        else:
            strength = "Weak"

        return {
            'score': score,
            'strength': strength,
            'feedback': feedback,
            'max_score': 6
        }

    def _validated_length_input(self, prompt: str, default: int = 16) -> int:
        """Read a positive integer length from input with fallback."""
        while True:
            raw = input(f"{prompt} (default: {default}): ").strip()
            if not raw:
                return default
            try:
                length = int(raw)
                if length <= 0:
                    print("Please enter a positive integer.")
                    continue
                return length
            except ValueError:
                print("Please enter a valid integer.")

    def generate_password(self, length: int = 16, use_uppercase: bool = True,
                          use_numbers: bool = True, use_special: bool = True) -> str:
        """Generate a strong random password with guaranteed character-class coverage."""
        # Build character pools
        pools = [string.ascii_lowercase]  # lowercase always allowed
        required_sets = [string.ascii_lowercase]  # ensure at least one lowercase by default

        if use_uppercase:
            pools.append(string.ascii_uppercase)
            required_sets.append(string.ascii_uppercase)
        if use_numbers:
            pools.append(string.digits)
            required_sets.append(string.digits)
        if use_special:
            pools.append(RE_SPECIALS)
            required_sets.append(RE_SPECIALS)

        # Validate feasibility: must have room for at least one from each required set
        if length < len(required_sets):
            raise ValueError(
                f"Password length {length} is too short for the selected requirements "
                f"({len(required_sets)} character categories)."
            )

        all_chars = ''.join(pools)

        # One guaranteed from each required set
        password_chars = [random.choice(s) for s in required_sets]
        # Fill the rest
        password_chars += [random.choice(all_chars) for _ in range(length - len(password_chars))]
        random.shuffle(password_chars)
        return ''.join(password_chars)

    def add_password_interactive(self):
        """Interactive function to add a new password"""
        print("\n=== Add New Password ===")

        website = input("Website/Service: ").strip()
        username = input("Username/Email: ").strip()
        category = input("Category (default: General): ").strip() or "General"

        print("\nPassword options:")
        print("1. Enter password manually")
        print("2. Generate strong password")

        choice = input("Choose option (1 or 2): ").strip()

        if choice == "2":
            length = self._validated_length_input("Password length", default=16)
            try:
                password = self.generate_password(length)
                print(f"Generated password: {password}")
            except ValueError as ve:
                print(f"Error: {ve}")
                return
        else:
            while True:
                password = getpass.getpass("Password: ")
                strength = self.password_strength_meter(password)

                print(f"\nPassword Strength: {strength['strength']} ({strength['score']}/{strength['max_score']})")
                if strength['feedback']:
                    print("Suggestions:")
                    for suggestion in strength['feedback']:
                        print(f"  - {suggestion}")

                confirm = input("\nUse this password? (y/n): ").lower().strip()
                if confirm == 'y':
                    break
                elif confirm == 'n':
                    # Loop back to re-enter and re-evaluate
                    continue
                else:
                    print("Invalid choice. Please answer y or n.")

        if self.db.add_password(website, username, password, category):
            print("✓ Password saved successfully!")
        else:
            print("✗ Failed to save password.")

    def view_passwords(self):
        """View all stored passwords"""
        print("\n=== Stored Passwords ===")
        passwords = self.db.get_all_passwords()

        if not passwords:
            print("No passwords stored yet.")
            return

        for i, pwd in enumerate(passwords, 1):
            print(f"\n{i}. {pwd['website']}")
            print(f"   Username: {pwd['username']}")
            print(f"   Password: {'*' * 12}")
            print(f"   Category: {pwd['category']}")
            print(f"   ID: {pwd['id']}")

    def search_passwords_interactive(self):
        """Search passwords interactively"""
        print("\n=== Search Passwords ===")
        query = input("Enter search term (website, username, or category): ").strip()

        if not query:
            print("Please enter a search term.")
            return

        results = self.db.search_passwords(query)

        if not results:
            print("No matching passwords found.")
            return

        print(f"\nFound {len(results)} matching password(s):")
        for i, pwd in enumerate(results, 1):
            print(f"\n{i}. {pwd['website']}")
            print(f"   Username: {pwd['username']}")
            print(f"   Category: {pwd['category']}")
            print(f"   ID: {pwd['id']}")

    def show_password_details(self):
        """Show detailed password information"""
        print("\n=== View Password Details ===")
        entry_id = input("Enter password entry ID: ").strip()

        if not entry_id.isdigit():
            print("Invalid ID format.")
            return

        password_entry = self.db.get_password(int(entry_id))

        if not password_entry:
            print("Password entry not found.")
            return

        print(f"\nWebsite: {password_entry['website']}")
        print(f"Username: {password_entry['username']}")
        print(f"Password: {password_entry['password']}")
        print(f"Category: {password_entry['category']}")

        # Show password strength
        strength = self.password_strength_meter(password_entry['password'])
        print(f"Strength: {strength['strength']} ({strength['score']}/{strength['max_score']})")

    def update_password_interactive(self):
        """Update password entry interactively"""
        print("\n=== Update Password ===")
        entry_id = input("Enter password entry ID to update: ").strip()

        if not entry_id.isdigit():
            print("Invalid ID format.")
            return

        current_entry = self.db.get_password(int(entry_id))
        if not current_entry:
            print("Password entry not found.")
            return

        print(f"\nCurrent details:")
        print(f"Website: {current_entry['website']}")
        print(f"Username: {current_entry['username']}")
        print(f"Category: {current_entry['category']}")

        website = input(f"New website (current: {current_entry['website']}): ").strip() or current_entry['website']
        username = input(f"New username (current: {current_entry['username']}): ").strip() or current_entry['username']
        category = input(f"New category (current: {current_entry['category']}): ").strip() or current_entry['category']

        print("\nPassword options:")
        print("1. Keep current password")
        print("2. Enter new password")
        print("3. Generate new password")

        choice = input("Choose option (1, 2, or 3): ").strip()

        if choice == "1":
            password = current_entry['password']
        elif choice == "2":
            # same confirm loop as add()
            while True:
                password = getpass.getpass("New password: ")
                strength = self.password_strength_meter(password)
                print(f"\nPassword Strength: {strength['strength']} ({strength['score']}/{strength['max_score']})")
                if strength['feedback']:
                    print("Suggestions:")
                    for suggestion in strength['feedback']:
                        print(f"  - {suggestion}")
                confirm = input("\nUse this password? (y/n): ").lower().strip()
                if confirm in ('y', 'n'):
                    if confirm == 'y':
                        break
                else:
                    print("Invalid choice. Please answer y or n.")
        elif choice == "3":
            length = self._validated_length_input("Password length", default=16)
            try:
                password = self.generate_password(length)
                print(f"Generated password: {password}")
            except ValueError as ve:
                print(f"Error: {ve}")
                return
        else:
            print("Invalid choice. Keeping current password.")
            password = current_entry['password']

        if self.db.update_password(int(entry_id), website, username, password, category):
            print("✓ Password updated successfully!")
        else:
            print("✗ Failed to update password.")

    def delete_password_interactive(self):
        """Delete password entry interactively"""
        print("\n=== Delete Password ===")
        entry_id = input("Enter password entry ID to delete: ").strip()

        if not entry_id.isdigit():
            print("Invalid ID format.")
            return

        current_entry = self.db.get_password(int(entry_id))
        if not current_entry:
            print("Password entry not found.")
            return

        print(f"\nYou are about to delete:")
        print(f"Website: {current_entry['website']}")
        print(f"Username: {current_entry['username']}")

        confirm = input("\nAre you sure? (y/n): ").lower().strip()
        if confirm == 'y':
            if self.db.delete_password(int(entry_id)):
                print("✓ Password deleted successfully!")
            else:
                print("✗ Failed to delete password.")
        else:
            print("Deletion cancelled.")

    def generate_password_interactive(self):
        """Interactive password generator"""
        print("\n=== Password Generator ===")

        length = self._validated_length_input("Password length", default=16)
        use_uppercase = input("Include uppercase letters? (y/n, default: y): ").lower().strip() != 'n'
        use_numbers = input("Include numbers? (y/n, default: y): ").lower().strip() != 'n'
        use_special = input("Include special characters? (y/n, default: y): ").lower().strip() != 'n'

        try:
            password = self.generate_password(length, use_uppercase, use_numbers, use_special)
        except ValueError as ve:
            print(f"Error: {ve}")
            return

        print(f"\nGenerated Password: {password}")

        # Show strength analysis
        strength = self.password_strength_meter(password)
        print(f"Strength: {strength['strength']} ({strength['score']}/{strength['max_score']})")

    def show_menu(self):
        """Display main menu"""
        print("\n" + "=" * 50)
        print("          PASSWORD VAULT")
        print("=" * 50)
        print("1. View All Passwords")
        print("2. Add New Password")
        print("3. Search Passwords")
        print("4. View Password Details")
        print("5. Update Password")
        print("6. Delete Password")
        print("7. Generate Password")
        print("8. View Categories")
        print("9. Exit")
        print("=" * 50)

    def run(self):
        """Main application loop"""
        self.authenticate()

        if not self.is_authenticated:
            return

        while True:
            self.show_menu()
            choice = input("Enter your choice (1-9): ").strip()

            try:
                if choice == '1':
                    self.view_passwords()
                elif choice == '2':
                    self.add_password_interactive()
                elif choice == '3':
                    self.search_passwords_interactive()
                elif choice == '4':
                    self.show_password_details()
                elif choice == '5':
                    self.update_password_interactive()
                elif choice == '6':
                    self.delete_password_interactive()
                elif choice == '7':
                    self.generate_password_interactive()
                elif choice == '8':
                    self.show_categories()
                elif choice == '9':
                    print("Goodbye! Stay secure! 🔒")
                    break
                else:
                    print("Invalid choice. Please enter a number between 1-9.")
            except Exception as e:
                print(f"An error occurred: {e}")

    def show_categories(self):
        """Show all categories"""
        print("\n=== Categories ===")
        categories = self.db.get_categories()

        if not categories:
            print("No categories found.")
            return

        for i, category in enumerate(categories, 1):
            print(f"{i}. {category}")


if __name__ == "__main__":
    vault = PasswordVault()
    vault.run()
