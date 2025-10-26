# test_db.py
import os
from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError, ProgrammingError

print("Memuat variabel dari file .env...")
load_dotenv() # Reads the .env file

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    print("❌ GAGAL! Variabel DATABASE_URL tidak ditemukan di file .env!")
    print("   Pastikan file .env ada di folder yang sama dan berisi baris DATABASE_URL=...")
else:
    print(f"Mencoba terhubung ke: {DATABASE_URL[:DATABASE_URL.find('@')] + '@...'}") # Hide password in log
    try:
        # Create the engine WITHOUT connect_args for PostgreSQL
        engine = create_engine(DATABASE_URL)

        # Try to establish a connection and run a simple query
        with engine.connect() as connection:
            result = connection.execute(text("SELECT 1")) # Simple test query
            for row in result:
                if row[0] == 1:
                    print("✅ SUKSES! Koneksi ke database Supabase berhasil.")
                else:
                    # This case should ideally not happen with SELECT 1
                    print("🟡 Koneksi berhasil, tapi query 'SELECT 1' mengembalikan hasil yang tak terduga.")

    except OperationalError as e:
        print(f"❌ GAGAL! Terjadi OperationalError (Biasanya masalah jaringan, firewall, atau host/port salah):")
        print(f"   {e}")
    except ProgrammingError as e:
        print(f"❌ GAGAL! Terjadi ProgrammingError (Biasanya masalah otentikasi/password salah atau database tidak ada):")
        print(f"   {e}")
    except Exception as e:
        # Catch any other unexpected errors
        print(f"❌ GAGAL! Terjadi error tak terduga:")
        print(f"   {e}")