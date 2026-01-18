# NativeGhost 👻

**NativeGhost** adalah emulator Android berbasis Rust yang menggunakan **Unicorn Engine** untuk menjalankan dan men-debug native library Android (`.so`) secara terisolasi. Proyek ini dikembangkan khusus untuk menganalisis library **Mobile Legends: Bang Bang (MLBB)**, yaitu `libbyteplusaudio.so`.

## 🎯 Tujuan Utama
Mengekstraksi **API Request** (URL, Headers, Payload) untuk **Top Global Leaderboard Match History**. Data yang dicari meliputi:
- Hasil Pertandingan (Win/Lose)
- Hero yang digunakan (Tim & Musuh)
- Durasi Pertandingan

## 🚀 Fitur
- **Emulasi ARM64**: Menjalankan instruksi native ARM64 menggunakan Unicorn Engine.
- **JNI Mocking**: Mensimulasikan lingkungan Java/JNI (JavaVM, JNIEnv) untuk membohongi library agar berjalan tanpa Android asli.
- **Hooking System**:
  - `dlsym` & `dlopen`: Menangani pemuatan library dinamis.
  - `__android_log_write`: Menangkap log internal SDK (termasuk `libjingle`).
  - `sendto` / `write`: Menginspeksi lalu lintas jaringan keluar.
- **Memory Scanner**: Memindai Heap dan Stack untuk menemukan string sensitif (seperti token atau JSON) sebelum aplikasi keluar.

## 🛠️ Cara Penggunaan
Pastikan Rust dan resource library (`memory_dump.bin`, `imports_map.txt`) sudah tersedia.

```bash
# Masuk ke direktori emulator
cd emulator_rust

# Jalankan dalam mode release (untuk kecepatan)
cargo run --release
```

## 📂 Struktur Proyek
- `src/main.rs`: Kode utama emulator (JNI handling, Memory Map, Hooks).
- `memory_dump.bin`: Dump memori dari proses asli (16MB+).
- `imports_map.txt`: Peta offset fungsi impor (PLT).
- `scripts/`: Alat bantu (disassembly, symbol dumping).
- `docs/`: Dokumentasi teknis dan handover context.

---
*Dibuat untuk tujuan edukasi dan riset keamanan.*
