import streamlit as st
from database import init_db

init_db()

# Clean Sidebar
with st.sidebar:
    st.title("🔒 AES Encryption App")
    
    if "user_id" not in st.session_state:
        page = st.radio("Navigate", ["Login", "Signup"])
    else:
        page = st.radio(
            "Navigate",
            ["Upload & Encrypt", "Encrypted Files", "Change Password"],
        )
        
        # Logout button - style it properly
        if st.button("🚪 Logout", use_container_width=True):
            st.session_state.clear()
            st.success("Logged out successfully!")
            st.rerun()

# Page Routing
if page == "Login":
    from pages import Login
elif page == "Signup":
    from pages import Signup
elif page == "Upload & Encrypt":
    from pages import Upload_and_Encrypt
elif page == "Encrypted Files":
    from pages import Encrypted_Files
elif page == "Change Password":
    from pages import Change_Password
