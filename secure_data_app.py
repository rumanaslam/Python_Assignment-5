import streamlit as st
import hashlib
import time
import json
import base64
from cryptography.fernet import Fernet
import uuid

# Initialize session variables
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}
if 'current_page' not in st.session_state:
    st.session_state.current_page = "Home"
if 'last_attempt_time' not in st.session_state:
    st.session_state.last_attempt_time = 0

# Functions
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def create_fernet_key(passkey):
    hashed = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(hashed[:32])

def encrypt_text(data, passkey):
    key = create_fernet_key(passkey)
    return Fernet(key).encrypt(data.encode()).decode()

def decrypt_text(encrypted_data, passkey, data_id):
    try:
        hashed_pass = hash_passkey(passkey)
        record = st.session_state.stored_data.get(data_id)

        if record and record["passkey"] == hashed_pass:
            key = create_fernet_key(passkey)
            return Fernet(key).decrypt(record["encrypted_text"].encode()).decode()
        else:
            st.session_state.failed_attempts += 1
            st.session_state.last_attempt_time = time.time()
            return None
    except:
        st.session_state.failed_attempts += 1
        st.session_state.last_attempt_time = time.time()
        return None

def reset_attempts():
    st.session_state.failed_attempts = 0

def navigate_to(page):
    st.session_state.current_page = page

def generate_id():
    return str(uuid.uuid4())

# Title
st.title("🔐 Encrypted Data Vault")

# Sidebar Navigation
options = ["Home", "Save Data", "Access Data", "Login"]
selected = st.sidebar.radio("Go to", options, index=options.index(st.session_state.current_page))
st.session_state.current_page = selected

# Lock after 3 failed tries
if st.session_state.failed_attempts >= 3:
    st.session_state.current_page = "Login"
    st.warning("🔐 Too many failed attempts. Please reauthorize.")

# Page Logic
if st.session_state.current_page == "Home":
    st.subheader("🏠 Welcome to Your Secure Vault")
    st.markdown("Easily **encrypt** your text and **retrieve it** using your secret passkey.")
    
    col1, col2 = st.columns(2)
    if col1.button("➕ Save New"):
        navigate_to("Save Data")
    if col2.button("🔓 Access Saved"):
        navigate_to("Access Data")

    st.info(f"🔒 Stored Entries: `{len(st.session_state.stored_data)}`")

elif st.session_state.current_page == "Save Data":
    st.subheader("🗂️ Store Confidential Data")

    text_input = st.text_area("🔏 Enter your message:")
    key1 = st.text_input("🔑 Choose a passkey", type="password")
    key2 = st.text_input("✅ Confirm passkey", type="password")

    if st.button("🔐 Encrypt & Save"):
        if text_input and key1 and key2:
            if key1 != key2:
                st.error("❌ Passkeys do not match.")
            else:
                uid = generate_id()
                hashed = hash_passkey(key1)
                encrypted = encrypt_text(text_input, key1)
                st.session_state.stored_data[uid] = {
                    "encrypted_text": encrypted,
                    "passkey": hashed
                }
                st.success("✅ Data secured successfully!")
                st.code(uid, language="text")
                st.info("💡 Save this ID to retrieve your data later.")
        else:
            st.warning("⚠️ All fields are required.")

elif st.session_state.current_page == "Access Data":
    st.subheader("🔍 Retrieve Encrypted Data")

    remaining = 3 - st.session_state.failed_attempts
    st.info(f"🧮 Attempts left: `{remaining}`")

    retrieve_id = st.text_input("📄 Enter Data ID")
    retrieve_key = st.text_input("🔑 Enter Passkey", type="password")

    if st.button("🔓 Decrypt"):
        if retrieve_id and retrieve_key:
            if retrieve_id in st.session_state.stored_data:
                encrypted_value = st.session_state.stored_data[retrieve_id]["encrypted_text"]
                result = decrypt_text(encrypted_value, retrieve_key, retrieve_id)

                if result:
                    st.success("✅ Decryption successful!")
                    st.markdown("### 🔍 Retrieved Data:")
                    st.code(result, language="text")
                    reset_attempts()
                else:
                    st.error(f"❌ Incorrect passkey. {remaining - 1} attempts left.")
            else:
                st.error("⚠️ Data ID not found.")
            
            if st.session_state.failed_attempts >= 3:
                st.warning("🔒 Too many failed tries. Redirecting to Login.")
                st.rerun()
        else:
            st.warning("⚠️ Please provide all inputs.")

elif st.session_state.current_page == "Login":
    st.subheader("🔑 Admin Login Required")

    wait_seconds = 10
    time_elapsed = time.time() - st.session_state.last_attempt_time

    if time_elapsed < wait_seconds and st.session_state.failed_attempts >= 3:
        wait_left = int(wait_seconds - time_elapsed)
        st.warning(f"⏳ Please wait `{wait_left}` seconds before trying again.")
    else:
        master_pass = st.text_input("🔐 Enter Admin Password", type="password")
        if st.button("Login"):
            if master_pass == "admin123":
                reset_attempts()
                st.success("✅ Access granted.")
                navigate_to("Home")
                st.rerun()
            else:
                st.error("❌ Wrong password.")

# Footer
st.markdown("---")
st.caption("🔒 Encrypted Data Vault | Built for Learning")
