import os
import time
import pandas as pd
import streamlit as st
from sqlalchemy import create_engine, text, Engine
from sqlalchemy.exc import IntegrityError
from passlib.context import CryptContext

# --------------------
# INIT SESSION STATE (Perbaikan Utama)
# --------------------
if "master_auth_ok" not in st.session_state:
    st.session_state.master_auth_ok = False
if "show_form" not in st.session_state:
    st.session_state.show_form = False

# --------------------
# KONFIGURASI APLIKASI
# --------------------
st.set_page_config(page_title="Admin - Manajemen User", page_icon="🔑", layout="centered")
st.title("🔑 Manajemen User Registry Hemofilia Indonesia")

# -----------------------------
# KONEKSI DATABASE
# -----------------------------
def _resolve_db_url() -> str:
    # Mengambil langsung dari root secrets (sesuai komentar Anda bahwa header dihapus)
    url = st.secrets.get("DATABASE_URL")
    
    if not url:
        url = os.environ.get("DATABASE_URL")

    if url:
        if url.startswith("postgres://"):
            url = url.replace("postgres://", "postgresql://", 1)
        return url
    
    st.error("DATABASE_URL tidak ditemukan. Cek Secrets Streamlit.")
    st.stop()

@st.cache_resource(show_spinner="Menghubungkan ke database...")
def get_engine(dsn: str) -> Engine:
    try:
        engine = create_engine(dsn, pool_pre_ping=True)
        # Test koneksi
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return engine
    except Exception as e:
        st.error(f"Gagal terhubung ke database: {e}")
        st.stop()

DB_URL = _resolve_db_url()
DB_ENGINE = get_engine(DB_URL)

# Menggunakan bcrypt standar agar kompatibel
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --------------------
# DATA CABANG
# --------------------
@st.cache_data(show_spinner="Memuat daftar cabang...")
def fetch_cabang_list(_engine: Engine) -> list:
    try:
        # Pastikan tabel pwh.hmhi_cabang ada. Jika tidak, fungsi ini akan return default.
        query = text("SELECT DISTINCT cabang FROM pwh.hmhi_cabang WHERE cabang IS NOT NULL ORDER BY cabang")
        with _engine.connect() as conn:
            df = pd.read_sql(query, conn)
        # Dropdown list
        return [""] + df["cabang"].dropna().tolist()
    except Exception:
        # Fallback jika tabel hmhi_cabang belum dibuat/gagal akses
        return ["", "Pusat", "Aceh", "Sumatera Utara", "DKI Jakarta", "Jawa Barat", "Jawa Tengah", "DI Yogyakarta", "Jawa Timur", "Bali"]

# --------------------
# CEK MASTER KEY
# --------------------
def check_master_key():
    # Perbaikan: Konsisten mengambil dari root secrets, sama seperti DB URL
    MASTER_KEY = st.secrets.get("MASTER_KEY")
    
    if not MASTER_KEY:
        st.error("MASTER_KEY belum disetting di .streamlit/secrets.toml")
        st.stop()

    st.subheader("🔒 Verifikasi Admin Utama")
    st.warning("Halaman ini hanya untuk Super Admin (Pengurus Pusat/IT).")
    
    with st.form("auth_form"):
        master_key_input = st.text_input("Masukkan Master Key:", type="password")
        submitted = st.form_submit_button("Verifikasi", type="primary")
        
        if submitted:
            if master_key_input == MASTER_KEY:
                st.session_state.master_auth_ok = True
                st.success("Akses diterima!")
                time.sleep(1)
                st.rerun()
            else:
                st.error("Master Key salah.")

# --------------------
# FUNGSI DATA USER
# --------------------
def fetch_user_list(_engine: Engine):
    try:
        query = text("""
            SELECT id, username, cabang, 
                   COALESCE(to_char(created_at, 'YYYY-MM-DD HH24:MI'), '-') as created_at 
            FROM pwh.users 
            ORDER BY username ASC
        """)
        with _engine.connect() as conn:
            df = pd.read_sql(query, conn)
        return df
    except Exception as e:
        st.error(f"Gagal memuat data user: {e}")
        return pd.DataFrame()

def update_user_password(_engine: Engine, username: str, new_password: str):
    try:
        hashed = pwd_context.hash(new_password)
        with _engine.begin() as conn:
            conn.execute(
                text("UPDATE pwh.users SET hashed_password = :p WHERE username = :u"),
                {"p": hashed, "u": username},
            )
        st.toast(f"Password '{username}' berhasil diubah!", icon="✅")
        time.sleep(1)
    except Exception as e:
        st.error(f"Gagal update: {e}")

def delete_user(_engine: Engine, username: str):
    try:
        with _engine.begin() as conn:
            conn.execute(text("DELETE FROM pwh.users WHERE username = :u"), {"u": username})
        st.toast(f"User '{username}' dihapus!", icon="🗑️")
        time.sleep(1)
    except Exception as e:
        st.error(f"Gagal hapus: {e}")

# --------------------
# HALAMAN ADMIN
# --------------------
def admin_page():
    # Header & Logout
    c1, c2 = st.columns([3, 1])
    with c1:
        st.success("✅ Login sebagai Super Admin")
    with c2:
        if st.button("Logout"):
            st.session_state.master_auth_ok = False
            st.session_state.show_form = False
            st.rerun()

    tab1, tab2 = st.tabs(["➕ Buat User Baru", "📋 Daftar User"])

    # === TAB 1: FORM USER BARU ===
    with tab1:
        st.info("Buat akun untuk admin cabang/wilayah agar bisa mengakses aplikasi input.")
        cabang_options = fetch_cabang_list(DB_ENGINE)

        with st.form("create_user_form", clear_on_submit=True):
            col_u, col_c = st.columns(2)
            with col_u:
                username = st.text_input("Username (Tanpa Spasi)")
            with col_c:
                cabang = st.selectbox("Wilayah Cabang", options=cabang_options)
            
            password = st.text_input("Password", type="password")
            
            submitted = st.form_submit_button("Simpan User Baru", type="primary")

            if submitted:
                # Validasi
                if not username or not password or not cabang:
                    st.error("Username, Password, dan Cabang wajib diisi.")
                elif len(password) < 6:
                    st.error("Password minimal 6 karakter.")
                elif " " in username:
                    st.error("Username tidak boleh mengandung spasi.")
                else:
                    # Proses Simpan
                    try:
                        hashed_password = pwd_context.hash(password)
                        with DB_ENGINE.begin() as conn:
                            query = text("""
                                INSERT INTO pwh.users (username, hashed_password, cabang)
                                VALUES (:user, :pass, :branch)
                            """)
                            conn.execute(query, {"user": username.lower(), "pass": hashed_password, "branch": cabang})
                        
                        st.success(f"User '{username}' berhasil dibuat untuk cabang '{cabang}'!")
                        st.cache_data.clear() # Clear cache agar list user terupdate
                    except IntegrityError:
                        st.error(f"Username '{username}' sudah terpakai. Gunakan username lain.")
                    except Exception as e:
                        st.error(f"Error database: {e}")

    # === TAB 2: DAFTAR USER ===
    with tab2:
        st.subheader("Daftar Pengguna Aktif")
        
        # Tombol refresh manual jika perlu
        if st.button("🔄 Refresh Data"):
            st.cache_data.clear()
            st.rerun()

        df_users = fetch_user_list(DB_ENGINE)

        if df_users.empty:
            st.warning("Belum ada data user.")
        else:
            for i, row in df_users.iterrows():
                # Card style layout
                with st.expander(f"👤 {row.username} | 📍 {row.cabang}"):
                    st.caption(f"Dibuat pada: {row.created_at}")
                    
                    c_pass, c_act = st.columns([2, 1])
                    
                    with c_pass:
                        new_pw = st.text_input("Reset Password:", key=f"pw_{row.id}", type="password", placeholder="Isi jika ingin mengganti")
                        if st.button("Simpan Password Baru", key=f"btn_up_{row.id}"):
                            if len(new_pw) >= 6:
                                update_user_password(DB_ENGINE, row.username, new_pw)
                                st.rerun()
                            else:
                                st.error("Min 6 karakter")
                    
                    with c_act:
                        st.write("Area Berbahaya")
                        if st.button("Hapus User", key=f"btn_del_{row.id}", type="primary"):
                            delete_user(DB_ENGINE, row.username)
                            st.rerun()

# --------------------
# MAIN LOGIC FLOW
# --------------------
if not st.session_state.master_auth_ok:
    check_master_key()
else:
    admin_page()