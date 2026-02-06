import os
import time
import pandas as pd
import streamlit as st
from sqlalchemy import create_engine, text, Engine
from sqlalchemy.exc import IntegrityError
from passlib.context import CryptContext

# --------------------
# 1. KONFIGURASI HALAMAN & STATE
# --------------------
st.set_page_config(
    page_title="Admin Panel - Registry Hemofilia", 
    page_icon="🛡️", 
    layout="centered"
)

# Init Session State
if "master_auth_ok" not in st.session_state:
    st.session_state.master_auth_ok = False

# --------------------
# 2. KONEKSI DATABASE & KEAMANAN
# --------------------
def _resolve_db_url() -> str:
    url = st.secrets.get("DATABASE_URL") or os.environ.get("DATABASE_URL")
    if url and url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    if not url:
        st.error("🚨 DATABASE_URL tidak ditemukan.")
        st.stop()
    return url

@st.cache_resource(show_spinner=False)
def get_engine(dsn: str) -> Engine:
    try:
        return create_engine(dsn, pool_pre_ping=True)
    except Exception as e:
        st.error(f"Koneksi DB Gagal: {e}")
        st.stop()

DB_ENGINE = get_engine(_resolve_db_url())

# SECURITY: Menggunakan PBKDF2 (Aman & Tidak ada limit 72 bytes)
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

def hash_safe(password: str) -> str:
    """Hashing aman tanpa limit panjang karakter."""
    return pwd_context.hash(password.strip())

# --------------------
# 3. FUNGSI DATA (CRUD)
# --------------------
@st.cache_data
def fetch_cabang_list() -> list:
    try:
        with DB_ENGINE.connect() as conn:
            df = pd.read_sql(text("SELECT DISTINCT cabang FROM pwh.hmhi_cabang ORDER BY cabang"), conn)
        return [""] + df["cabang"].dropna().tolist()
    except:
        return ["", "Pusat", "Jawa Barat", "DKI Jakarta"] # Fallback

def fetch_users():
    query = """
        SELECT id, username, cabang, 
               to_char(created_at, 'DD Mon YYYY, HH24:MI') as tgl_dibuat 
        FROM pwh.users ORDER BY username ASC
    """
    with DB_ENGINE.connect() as conn:
        return pd.read_sql(text(query), conn)

def add_user_to_db(username, password, cabang):
    hashed = hash_safe(password)
    with DB_ENGINE.begin() as conn:
        conn.execute(
            text("INSERT INTO pwh.users (username, hashed_password, cabang) VALUES (:u, :p, :c)"),
            {"u": username.lower(), "p": hashed, "c": cabang}
        )

def update_password_db(username, new_password):
    hashed = hash_safe(new_password)
    with DB_ENGINE.begin() as conn:
        conn.execute(
            text("UPDATE pwh.users SET hashed_password = :p WHERE username = :u"),
            {"p": hashed, "u": username}
        )

def delete_user_db(username):
    with DB_ENGINE.begin() as conn:
        conn.execute(text("DELETE FROM pwh.users WHERE username = :u"), {"u": username})

# --------------------
# 4. HALAMAN LOGIN ADMIN
# --------------------
def check_master_key():
    st.markdown("""
    <div style='text-align: center; padding: 20px;'>
        <h1>🔒 Akses Super Admin</h1>
        <p>Silakan masukkan Master Key untuk mengakses manajemen user.</p>
    </div>
    """, unsafe_allow_html=True)
    
    with st.form("login_form"):
        key_input = st.text_input("Master Key", type="password", placeholder="••••••••")
        if st.form_submit_button("Buka Gembok 🔓", type="primary", use_container_width=True):
            if key_input == st.secrets.get("MASTER_KEY"):
                st.session_state.master_auth_ok = True
                st.toast("Login Berhasil!", icon="✅")
                time.sleep(0.5)
                st.rerun()
            else:
                st.error("Kunci salah. Akses ditolak.")

# --------------------
# 5. HALAMAN UTAMA (DASHBOARD)
# --------------------
def admin_dashboard():
    # Header
    c1, c2 = st.columns([3, 1])
    with c1:
        st.title("🛡️ Manajemen User")
        st.caption("Kelola akun admin wilayah untuk Registry Hemofilia Indonesia")
    with c2:
        st.write("") # Spacer
        if st.button("Logout 🚪", use_container_width=True):
            st.session_state.master_auth_ok = False
            st.rerun()

    st.divider()

    # Tabs UI (DITAMBAHKAN TAB DEBUG)
    tab_create, tab_list, tab_debug = st.tabs(["➕ Buat User Baru", "📋 Daftar User Aktif", "🔍 Debug / Test Login"])

    # === TAB 1: FORM BUAT USER ===
    with tab_create:
        st.markdown("##### Input Data Admin Baru")
        
        with st.container(border=True):
            with st.form("add_user_form", clear_on_submit=True):
                col_a, col_b = st.columns(2)
                with col_a:
                    u_input = st.text_input("Username", placeholder="misal: admin_jabar", help="Gunakan huruf kecil tanpa spasi")
                with col_b:
                    c_input = st.selectbox("Wilayah Cabang", fetch_cabang_list())
                
                p_input = st.text_input("Password", type="password", placeholder="Minimal 6 karakter")
                
                st.write("")
                if st.form_submit_button("Simpan User", type="primary", use_container_width=True):
                    # Validasi
                    u, p = u_input.strip(), p_input.strip()
                    if not u or not p or not c_input:
                        st.warning("⚠️ Semua kolom wajib diisi.")
                    elif len(p) < 6:
                        st.warning("⚠️ Password terlalu pendek (min 6 karakter).")
                    elif " " in u:
                        st.warning("⚠️ Username tidak boleh ada spasi.")
                    else:
                        try:
                            add_user_to_db(u, p, c_input)
                            st.success(f"✅ Sukses! User **{u}** untuk cabang **{c_input}** berhasil dibuat.")
                            st.cache_data.clear() # Clear cache agar list update
                            time.sleep(1.5)
                        except IntegrityError:
                            st.error(f"⛔ Username **{u}** sudah terpakai. Coba yang lain.")
                        except Exception as e:
                            st.error(f"Error sistem: {e}")

    # === TAB 2: LIST USER ===
    with tab_list:
        col_head, col_btn = st.columns([4,1])
        with col_head:
            st.markdown("##### Daftar Akun Terdaftar")
        with col_btn:
            if st.button("🔄 Refresh"):
                st.cache_data.clear()
                st.rerun()

        try:
            df_users = fetch_users()
            if df_users.empty:
                st.info("Belum ada data user.")
            else:
                for idx, row in df_users.iterrows():
                    # Expander Styling
                    with st.expander(f"👤 **{row.username}** (📍 {row.cabang})"):
                        st.caption(f"📅 Dibuat pada: {row.tgl_dibuat}")
                        
                        # Layout dalam expander
                        c_reset, c_delete = st.columns([2, 1])
                        
                        # Bagian Reset Password
                        with c_reset:
                            st.markdown("**Ganti Password**")
                            new_pw = st.text_input("Password Baru", key=f"pw_{row.id}", type="password", label_visibility="collapsed", placeholder="Ketik password baru...")
                            if st.button("Update Password", key=f"btn_up_{row.id}"):
                                clean_pw = new_pw.strip()
                                if len(clean_pw) >= 6:
                                    update_password_db(row.username, clean_pw)
                                    st.toast(f"Password {row.username} berhasil diubah!", icon="✅")
                                else:
                                    st.toast("Gagal: Password minimal 6 karakter.", icon="⚠️")

                        # Bagian Delete
                        with c_delete:
                            st.markdown("**Zona Bahaya**")
                            if st.button("🗑️ Hapus Akun", key=f"btn_del_{row.id}", type="primary"):
                                delete_user_db(row.username)
                                st.toast(f"User {row.username} dihapus!", icon="🗑️")
                                time.sleep(1)
                                st.rerun()
                                
        except Exception as e:
            st.error(f"Gagal memuat data: {e}")

    # === TAB 3: DEBUG LOGING (DITAMBAHKAN) ===
    with tab_debug:
        st.warning("🛠️ Fitur ini hanya untuk testing verifikasi password (Debugging).")
        
        d_user = st.text_input("Test Username", key="d_user")
        d_pass = st.text_input("Test Password", key="d_pass", type="password")
        
        if st.button("Test Login Check"):
            with DB_ENGINE.connect() as conn:
                # Ambil data user dari DB
                query = text("SELECT username, hashed_password FROM pwh.users WHERE username = :u")
                result = conn.execute(query, {"u": d_user.strip()})
                user_data = result.mappings().fetchone()
            
            if not user_data:
                st.error("User tidak ditemukan di database.")
            else:
                st.info("User ditemukan, memulai pengecekan...")
                
                # --- MULAI KODE DEBUG REQUEST ANDA ---
                password = d_pass # Mengambil input dari form diatas
                
                password_to_check = password  # atau variabel apapun yang Anda masukkan
                
                # --- DEBUGGING SEMENTARA ---
                st.write(f"String yang dicek: {password_to_check}")
                st.write(f"Panjang karakter: {len(password_to_check)}")
                st.write(f"Tipe data: {type(password_to_check)}")
                
                # Tampilkan Hash dari DB juga untuk perbandingan
                st.code(f"Hash di DB: {user_data['hashed_password']}")
                # ---------------------------

                if pwd_context.verify(password_to_check, user_data['hashed_password']):
                    st.success("✅ PASSWORD COCOK / VALID!")
                    st.balloons()
                else:
                    st.error("❌ PASSWORD SALAH / TIDAK COCOK!")
                # --- AKHIR KODE DEBUG ---

# --------------------
# MAIN EXECUTION
# --------------------
if __name__ == "__main__":
    if not st.session_state.master_auth_ok:
        check_master_key()
    else:
        admin_dashboard()
