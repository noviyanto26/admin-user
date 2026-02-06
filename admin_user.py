import os
import time
import pandas as pd
import streamlit as st
from sqlalchemy import create_engine, text, Engine
from sqlalchemy.exc import IntegrityError
from passlib.context import CryptContext

# --------------------
# INIT SESSION STATE
# --------------------
if "master_auth_ok" not in st.session_state:
    st.session_state.master_auth_ok = False
if "show_form" not in st.session_state:
    st.session_state.show_form = False

# --------------------
# KONFIGURASI APLIKASI
# --------------------
st.set_page_config(page_title="Admin User", page_icon="🛡️", layout="centered")
st.title("🛡️ Manajemen User (PBKDF2)")

# INDIKATOR DEBUG (Agar Anda yakin kode baru yang jalan)
st.sidebar.success("System Status: Updated (v3.0)")

# -----------------------------
# KONEKSI DATABASE
# -----------------------------
def _resolve_db_url() -> str:
    url = st.secrets.get("DATABASE_URL")
    if not url:
        url = os.environ.get("DATABASE_URL")
    if url and url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    if not url:
        st.error("DATABASE_URL tidak ditemukan.")
        st.stop()
    return url

@st.cache_resource(show_spinner="Koneksi DB...")
def get_engine(dsn: str) -> Engine:
    try:
        engine = create_engine(dsn, pool_pre_ping=True)
        return engine
    except Exception as e:
        st.error(f"DB Error: {e}")
        st.stop()

DB_URL = _resolve_db_url()
DB_ENGINE = get_engine(DB_URL)

# --------------------
# KEAMANAN PASSWORD (GANTI ALGORITMA)
# --------------------
# KITA GANTI KE 'pbkdf2_sha256'.
# Algoritma ini TIDAK punya limit 72 bytes seperti Bcrypt.
# Jadi password sepanjang apapun (misal 500 karakter) aman.
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

def hash_safe(password: str) -> str:
    """
    Hashing menggunakan PBKDF2-SHA256.
    Aman, standar industri, dan tanpa limit panjang karakter.
    """
    try:
        return pwd_context.hash(password.strip())
    except Exception as e:
        raise ValueError(f"Hashing failed: {e}")

# --------------------
# DATA CABANG
# --------------------
@st.cache_data
def fetch_cabang_list(_engine: Engine) -> list:
    try:
        query = text("SELECT DISTINCT cabang FROM pwh.hmhi_cabang WHERE cabang IS NOT NULL ORDER BY cabang")
        with _engine.connect() as conn:
            df = pd.read_sql(query, conn)
        return [""] + df["cabang"].dropna().tolist()
    except Exception:
        return ["", "Pusat", "Jawa Barat", "DKI Jakarta"] # Fallback

# --------------------
# CEK MASTER KEY
# --------------------
def check_master_key():
    MASTER_KEY = st.secrets.get("MASTER_KEY")
    if not MASTER_KEY:
        st.error("Set MASTER_KEY di secrets.toml")
        st.stop()

    st.subheader("🔒 Login Super Admin")
    
    with st.form("auth_form"):
        # Tambahkan key unik agar state tidak nyangkut
        mk_input = st.text_input("Master Key:", type="password", key="mk_input_field")
        if st.form_submit_button("Masuk"):
            if mk_input == MASTER_KEY:
                st.session_state.master_auth_ok = True
                st.rerun()
            else:
                st.error("Kunci salah.")

# --------------------
# LOGIC ADMIN
# --------------------
def fetch_users(_engine):
    with _engine.connect() as conn:
        return pd.read_sql(text("SELECT id, username, cabang, created_at FROM pwh.users ORDER BY username"), conn)

def admin_page():
    st.write(f"Login: Super Admin")
    if st.button("Logout"):
        st.session_state.master_auth_ok = False
        st.rerun()

    tab1, tab2 = st.tabs(["➕ Tambah User", "📋 List User"])

    # TAB 1: TAMBAH USER
    with tab1:
        cabangs = fetch_cabang_list(DB_ENGINE)
        with st.form("add_user"):
            u = st.text_input("Username").strip()
            c = st.selectbox("Cabang", cabangs)
            p = st.text_input("Password", type="password").strip()
            
            if st.form_submit_button("Simpan"):
                if u and c and len(p) >= 6:
                    try:
                        # Hash password dengan PBKDF2
                        h = hash_safe(p)
                        with DB_ENGINE.begin() as conn:
                            conn.execute(
                                text("INSERT INTO pwh.users (username, hashed_password, cabang) VALUES (:u, :h, :c)"),
                                {"u": u.lower(), "h": h, "c": c}
                            )
                        st.success(f"Sukses: {u}")
                        time.sleep(1)
                        st.rerun()
                    except IntegrityError:
                        st.error("Username sudah ada.")
                    except Exception as e:
                        st.error(f"Error: {e}")
                else:
                    st.warning("Isi semua data. Password min 6 char.")

    # TAB 2: LIST USER
    with tab2:
        if st.button("Refresh"): st.rerun()
        
        try:
            df = fetch_users(DB_ENGINE)
            for _, row in df.iterrows():
                with st.expander(f"{row['username']} ({row['cabang']})"):
                    # Fitur Reset Password
                    new_p = st.text_input("Password Baru", key=f"p_{row['id']}", type="password").strip()
                    if st.button("Update Password", key=f"btn_{row['id']}"):
                        if len(new_p) >= 6:
                            h = hash_safe(new_p)
                            with DB_ENGINE.begin() as conn:
                                conn.execute(text("UPDATE pwh.users SET hashed_password = :h WHERE username = :u"), {"h": h, "u": row['username']})
                            st.toast("Password diupdate!")
                        else:
                            st.error("Min 6 karakter")
                    
                    # Fitur Hapus
                    st.write("---")
                    if st.button("Hapus User", key=f"del_{row['id']}", type="primary"):
                        with DB_ENGINE.begin() as conn:
                            conn.execute(text("DELETE FROM pwh.users WHERE username = :u"), {"u": row['username']})
                        st.rerun()
        except Exception as e:
            st.error(f"Gagal load data: {e}")

# MAIN
if not st.session_state.master_auth_ok:
    check_master_key()
else:
    admin_page()
