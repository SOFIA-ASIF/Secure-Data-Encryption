import streamlit as st
import json
import os
import hashlib
import base64
from cryptography.fernet import Fernet

# File paths
USER_FILE = "users.json"
DATA_FILE = "data.json"

# Load or initialize JSON data
def load_json(filepath):
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            return json.load(f)
    return {}

def save_json(filepath, data):
    with open(filepath, "w") as f:
        json.dump(data, f, indent=4)

# Hash passkey for secure storage
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Generate a Fernet encryption key from hashed passkey
def generate_fernet_key(passkey):
    hashed = hashlib.sha256(passkey.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(hashed[:32]))

# Encrypt and decrypt
def encrypt_data(data, passkey):
    fernet = generate_fernet_key(passkey)
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data, passkey):
    try:
        fernet = generate_fernet_key(passkey)
        return fernet.decrypt(encrypted_data.encode()).decode()
    except Exception:
        return None

# Load users and data
users = load_json(USER_FILE)
data_store = load_json(DATA_FILE)

# Streamlit UI
st.title("🔐 Secure Data Storage System")

menu = ["Login", "Register"]
choice = st.sidebar.selectbox("Select Action", menu)

# Session state for login
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "current_user" not in st.session_state:
    st.session_state.current_user = None

# Registration Section
if choice == "Register":
    st.subheader("📝 Register New User")
    username = st.text_input("Enter Username")
    password = st.text_input("Enter Password", type="password")

    if st.button("Register"):
        if username in users:
            st.error("❌ Username already exists.")
        else:
            users[username] = hash_passkey(password)
            save_json(USER_FILE, users)
            st.success("✅ Registration successful! Please login.")

# Login Section
elif choice == "Login" and not st.session_state.logged_in:
    st.subheader("🔑 User Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in users and users[username] == hash_passkey(password):
            st.session_state.logged_in = True
            st.session_state.current_user = username
            st.success(f"✅ Logged in as {username}")
        else:
            st.error("❌ Invalid credentials")

# Main App (after login)
if st.session_state.logged_in:
    st.sidebar.success(f"Welcome, {st.session_state.current_user}")

    option = st.radio("Select Operation", ["Store Data", "Retrieve Data"])

    if option == "Store Data":
        st.subheader("📦 Store Encrypted Data")
        user_data = st.text_area("Enter data to store")
        data_passkey = st.text_input("Enter a unique passkey to encrypt your data", type="password")
        if st.button("Encrypt & Store"):
            if user_data and data_passkey:
                encrypted = encrypt_data(user_data, data_passkey)
                data_store[data_passkey] = {
                    "user": st.session_state.current_user,
                    "data": encrypted
                }
                save_json(DATA_FILE, data_store)
                st.success("✅ Data encrypted and stored successfully!")
            else:
                st.error("⚠️ All fields are required.")

    elif option == "Retrieve Data":
        st.subheader("🔍 Retrieve Encrypted Data")
        data_passkey = st.text_input("Enter your data passkey", type="password")
        if st.button("Retrieve"):
            if data_passkey in data_store and data_store[data_passkey]["user"] == st.session_state.current_user:
                encrypted_data = data_store[data_passkey]["data"]
                decrypted = decrypt_data(encrypted_data, data_passkey)
                if decrypted:
                    st.text_area("🔓 Decrypted Data", decrypted, height=200)
                else:
                    st.error("❌ Failed to decrypt. Wrong passkey.")
            else:
                st.error("❌ No data found for this passkey or you are not authorized.")
