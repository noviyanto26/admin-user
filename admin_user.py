import os
import time
import pandas as pd
import streamlit as st
from sqlalchemy import create_engine, text, Engine
from sqlalchemy.exc import IntegrityError
from passlib.context import CryptContext

# =========================================================
# SESSION STATE
# =========================================================
if "master_auth_ok" not in st.session_state:
    st.session_state.master_auth_ok = False

# =========================================================
# APP CONFIG
# =========================================================
st.set_page_config(
    page_title="Admin - Manajemen User",
    page_icon="🔑",
    layout="centered"
)
st.title("🔑 Manajemen User Registry Hemofilia Indonesia")

# =========================================================
# DATABASE CONNECTION
# =========================================================
def resolve_db_url() -> str:
    url = st.secrets.get("DATABASE_URL") or os.environ.get("DATABASE_URL")

    if not url:
        st.error("DATABASE_URL tidak ditemukan.")
        st.stop()

    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)

    return url


@st.cache_resource(show_spinner="Menghubungkan ke database...")
def get_engine(dsn: str) -> Engine:
    engine = create_engine(dsn, pool_pre_ping=True)
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    return engine


DB_ENGINE = get_engine(resolve_db_url())

# =========================================================
# PASSWORD SECURITY (FINAL)
# =========================================================
pwd_context = CryptContext(
    schemes=["bcrypt_sha256"],
    deprecated="auto"
)

def hash_password(password: str) -> str:
    return pwd_context.hash(password.strip())

# =========================================================
# MASTER KEY AUTH
# =========================================================
def check_master_key():
    MASTER_KEY = st.secrets.get("MASTER_KEY")

    if not MASTER_KEY:
        st.error("MASTER_KEY belum disetting.")
        st.stop()

    st.subheader("🔒 Verifikasi Super Admin")

    with st.form("auth_form"):
        key_input = st.text_input("Masukkan Master Key", type="password")
        submitted = st.form_submit_button("Verifikasi", type="primary")

        if submitted:
            if key_input == MASTER_KEY:
                st.session_state.master_auth_ok = True
                st.success("Akses diterima")
                time.sleep(0.5)
                st.rerun()
            else:
                st.error("Master Key salah")

# =========================================================
# DATA ACCESS
# =========================================================
@st.cache_data(show_spinner="Memuat daftar cabang...")
def fetch_cabang_list(engine: Engine) -> list:
    try:
        q = text("""
            SELECT DISTINCT cabang
            FROM pwh.hmhi_cabang
            WHERE cabang IS NOT NULL
            ORDER BY cabang
        """)
        with engine.connect() as conn:
            df = pd.read_sql(q, conn)
        return [""] + df["cabang"].tolist()
    except Exception:
        return ["", "Pusat", "DKI Jakarta", "Jawa Barat", "Jawa Tengah", "Jawa Timur"]


def fetch_users(engine: Engine) -> pd.DataFrame:
    q = text("""
        SELECT id, username, cabang,
               to_char(created_at, 'YYYY-MM-DD HH24:MI') AS created_at
        FROM pwh.users
        ORDER BY username
    """)
    with engine.connect() as conn:
        return pd.read_sql(q, conn)


def update_password(engine: Engine, username: str, password: str):
    hashed = hash_password(password)
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE pwh.users SET hashed_password = :p WHERE username = :u"),
            {"p": hashed, "u": username}
        )


def delete_user(engine: Engine, username: str):
    with engine.begin() as conn:
        conn.execute(
            text("DELETE FROM pwh.users WHERE username = :u"),
            {"u": username}
        )

# =========================================================
# ADMIN PAGE
# =========================================================
def admin_page():
    c1, c2 = st.columns([3, 1])
    with c1:
        st.success("✅ Login sebagai Super Admin")
    with c2:
        if st.button("Logout"):
            st.session_state.master_auth_ok = False
            st.rerun()

    tab_create, tab_list = st.tabs(["➕ Buat User", "📋 Daftar User"])

    # -----------------------------------------------------
    # CREATE USER
    # -----------------------------------------------------
    with tab_create:
        cabang_list = fetch_cabang_list(DB_ENGINE)

        with st.form("create_user", clear_on_submit=True):
            username = st.text_input("Username (tanpa spasi)")
            cabang = st.selectbox("Cabang", cabang_list)
            password = st.text_input(
                "Password",
                type="password",
                help="Minimal 6 karakter, disarankan passphrase"
            )

            submitted = st.form_submit_button("Simpan", type="primary")

            if submitted:
                if not username or not password or not cabang:
                    st.error("Semua field wajib diisi")
                elif " " in username:
                    st.error("Username tidak boleh mengandung spasi")
                elif len(password) < 6:
                    st.error("Password minimal 6 karakter")
                else:
                    try:
                        with DB_ENGINE.begin() as conn:
                            conn.execute(
                                text("""
                                    INSERT INTO pwh.users
                                    (username, hashed_password, cabang)
                                    VALUES (:u, :p, :c)
                                """),
                                {
                                    "u": username.lower(),
                                    "p": hash_password(password),
                                    "c": cabang
                                }
                            )
                        st.success("User berhasil dibuat")
                        st.cache_data.clear()
                    except IntegrityError:
                        st.error("Username sudah digunakan")

    # -----------------------------------------------------
    # USER LIST
    # -----------------------------------------------------
    with tab_list:
        if st.button("🔄 Refresh"):
            st.cache_data.clear()
            st.rerun()

        df = fetch_users(DB_ENGINE)

        if df.empty:
            st.warning("Belum ada user")
            return

        for _, row in df.iterrows():
            with st.expander(f"👤 {row.username} | 📍 {row.cabang}"):
                st.caption(f"Dibuat: {row.created_at}")

                new_pw = st.text_input(
                    "Reset Password",
                    type="password",
                    key=f"pw_{row.id}"
                )

                if st.button("Update Password", key=f"up_{row.id}"):
                    if len(new_pw) < 6:
                        st.error("Minimal 6 karakter")
                    else:
                        update_password(DB_ENGINE, row.username, new_pw)
                        st.success("Password diperbarui")
                        time.sleep(0.5)
                        st.rerun()

                if st.button("Hapus User", key=f"del_{row.id}", type="primary"):
                    delete_user(DB_ENGINE, row.username)
                    st.warning("User dihapus")
                    time.sleep(0.5)
                    st.rerun()

# =========================================================
# MAIN FLOW
# =========================================================
if not st.session_state.master_auth_ok:
    check_master_key()
else:
    admin_page()
