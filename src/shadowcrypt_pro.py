#!/usr/bin/env python3
"""
shadowcrypt_pro.py

ShadowCrypt Pro — PySide6 AES-GCM File Encryptor
Features:
 - PySide6 professional GUI (dark hacker theme)
 - AES-GCM with PBKDF2-derived key
 - Chunked streaming (low memory)
 - Threaded workers (UI stays responsive)
 - Settings: PBKDF2 iterations, chunk size
 - Console log, progress bar, About dialog

Dependencies:
    pip install PySide6 pycryptodome
"""

import sys
import os
from pathlib import Path
from functools import partial

from PySide6.QtCore import Qt, Signal, QThread, QObject
from PySide6.QtWidgets import (
    QApplication, QWidget, QMainWindow, QPushButton, QLabel, QLineEdit,
    QFileDialog, QHBoxLayout, QVBoxLayout, QFrame, QTextEdit, QProgressBar,
    QMessageBox, QSpinBox, QDialog, QFormLayout, QDialogButtonBox, QSizePolicy
)
from PySide6.QtGui import QFont

# Crypto imports
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

# ----------------------
# Config defaults
# ----------------------
DEFAULT_PBKDF2_ITERS = 200_000
DEFAULT_CHUNK = 64 * 1024  # 64 KB

# ----------------------
# Encryption helper functions (streaming)
# Format used in file: salt(16) | nonce(16) | ciphertext... | tag(16)
# ----------------------
def encrypt_file_gcm_chunked(input_path, output_path, password, pbkdf2_iters, chunk_size, progress_callback, log_callback):
    try:
        filesize = os.path.getsize(input_path)
        salt = get_random_bytes(16)
        key = PBKDF2(password, salt, dkLen=32, count=pbkdf2_iters)

        cipher = AES.new(key, AES.MODE_GCM)
        nonce = cipher.nonce

        with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
            fout.write(salt)
            fout.write(nonce)
            total_read = 0
            while True:
                chunk = fin.read(chunk_size)
                if not chunk:
                    break
                ct = cipher.encrypt(chunk)
                fout.write(ct)
                total_read += len(chunk)
                progress_callback(total_read, filesize)
            tag = cipher.digest()
            fout.write(tag)

        log_callback(f"Encrypted -> {output_path}")
        return True, None
    except Exception as e:
        log_callback(f"Encryption error: {e}")
        return False, str(e)


def decrypt_file_gcm_chunked(input_path, output_path, password, pbkdf2_iters, chunk_size, progress_callback, log_callback):
    try:
        filesize = os.path.getsize(input_path)
        if filesize < 48:
            msg = "File too small or not a valid encrypted file."
            log_callback(msg)
            return False, msg

        with open(input_path, 'rb') as fin:
            salt = fin.read(16)
            nonce = fin.read(16)
            # ciphertext length = total - 16(salt) -16(nonce) -16(tag)
            total_size = fin.seek(0, os.SEEK_END)
            ciphertext_len = total_size - (16 + 16 + 16)
            fin.seek(32)  # move to start of ciphertext

            key = PBKDF2(password, salt, dkLen=32, count=pbkdf2_iters)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

            read_bytes = 0
            with open(output_path, 'wb') as fout:
                remaining = ciphertext_len
                while remaining > 0:
                    to_read = chunk_size if remaining >= chunk_size else remaining
                    chunk = fin.read(to_read)
                    if not chunk:
                        break
                    remaining -= len(chunk)
                    read_bytes += len(chunk)
                    pt = cipher.decrypt(chunk)
                    fout.write(pt)
                    progress_callback(read_bytes, ciphertext_len)
                tag = fin.read(16)
                try:
                    cipher.verify(tag)
                    log_callback(f"Decrypted -> {output_path} (auth OK)")
                    return True, None
                except ValueError:
                    try:
                        fout.close()
                        os.remove(output_path)
                    except Exception:
                        pass
                    msg = "Authentication failed: wrong password or corrupted file."
                    log_callback(msg)
                    return False, msg
    except Exception as e:
        log_callback(f"Decryption error: {e}")
        return False, str(e)

# ----------------------
# Worker classes
# ----------------------
class WorkerSignals(QObject):
    progress = Signal(int)         # percent
    log = Signal(str)              # log line
    finished = Signal(bool, str)   # success, error_message_or_keyinfo

class EncryptWorker(QThread):
    def __init__(self, infile, outfile, password, iters, chunk):
        super().__init__()
        self.infile = infile
        self.outfile = outfile
        self.password = password
        self.iters = iters
        self.chunk = chunk
        self.signals = WorkerSignals()

    def run(self):
        def progress_cb(done, total):
            pct = int(done / total * 100) if total else 0
            self.signals.progress.emit(pct)

        def log_cb(msg):
            self.signals.log.emit(msg)

        ok, err = encrypt_file_gcm_chunked(self.infile, self.outfile, self.password, self.iters, self.chunk, progress_cb, log_cb)
        if ok:
            self.signals.finished.emit(True, f"Encrypted: {Path(self.outfile).name}")
        else:
            self.signals.finished.emit(False, err or "Unknown error")


class DecryptWorker(QThread):
    def __init__(self, infile, outfile, password, iters, chunk):
        super().__init__()
        self.infile = infile
        self.outfile = outfile
        self.password = password
        self.iters = iters
        self.chunk = chunk
        self.signals = WorkerSignals()

    def run(self):
        def progress_cb(done, total):
            pct = int(done / total * 100) if total else 0
            self.signals.progress.emit(pct)

        def log_cb(msg):
            self.signals.log.emit(msg)

        ok, err = decrypt_file_gcm_chunked(self.infile, self.outfile, self.password, self.iters, self.chunk, progress_cb, log_cb)
        if ok:
            self.signals.finished.emit(True, f"Decrypted: {Path(self.outfile).name}")
        else:
            self.signals.finished.emit(False, err or "Unknown error")

# ----------------------
# Settings dialog
# ----------------------
class SettingsDialog(QDialog):
    def __init__(self, parent, iters, chunk_kb):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setModal(True)
        layout = QFormLayout(self)

        self.iters_spin = QSpinBox()
        self.iters_spin.setRange(1000, 2_000_000)
        self.iters_spin.setValue(iters)
        layout.addRow("PBKDF2 iterations:", self.iters_spin)

        self.chunk_spin = QSpinBox()
        self.chunk_spin.setRange(1, 16 * 1024)  # in KB
        self.chunk_spin.setValue(chunk_kb)
        layout.addRow("Chunk size (KB):", self.chunk_spin)

        box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        box.accepted.connect(self.accept)
        box.rejected.connect(self.reject)
        layout.addRow(box)

    def values(self):
        return self.iters_spin.value(), self.chunk_spin.value()

# ----------------------
# Main Window
# ----------------------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ShadowCrypt Pro")
        self.resize(920, 560)
        # default settings
        self.pbkdf2_iters = DEFAULT_PBKDF2_ITERS
        self.chunk_size = DEFAULT_CHUNK

        # main layout: left sidebar + right content
        central = QWidget()
        self.setCentralWidget(central)
        hbox = QHBoxLayout(central)
        hbox.setContentsMargins(8, 8, 8, 8)
        hbox.setSpacing(10)

        # Sidebar (fixed width)
        sidebar = QFrame()
        sidebar.setFixedWidth(220)
        sidebar.setStyleSheet("background:#0b0b0b; border-radius:4px;")
        side_layout = QVBoxLayout(sidebar)
        side_layout.setContentsMargins(12,12,12,12)
        side_layout.setSpacing(10)

        title = QLabel("ShadowCrypt Pro")
        title.setStyleSheet("color:#00FF99;")
        title.setFont(QFont("Consolas", 16, QFont.Bold))
        side_layout.addWidget(title)

        subtitle = QLabel("Secure AES-GCM File Encryptor")
        subtitle.setStyleSheet("color:#00ff88;")
        subtitle.setFont(QFont("Consolas", 9))
        side_layout.addWidget(subtitle)

        side_layout.addSpacing(8)

        # file label + entry + browse
        file_label = QLabel("File:")
        file_label.setStyleSheet("color:#9fffbf")
        side_layout.addWidget(file_label)
        self.file_entry = QLineEdit()
        self.file_entry.setPlaceholderText("Select a file...")
        self.file_entry.setStyleSheet("background:#071107; color:#caffd6;")
        side_layout.addWidget(self.file_entry)
        browse_btn = QPushButton("Browse")
        browse_btn.setStyleSheet("background:#093009; color:#bfffc9;")
        browse_btn.clicked.connect(self.browse_file)
        side_layout.addWidget(browse_btn)

        # password
        side_layout.addSpacing(6)
        pw_label = QLabel("Password:")
        pw_label.setStyleSheet("color:#9fffbf")
        side_layout.addWidget(pw_label)

        self.pw_entry = QLineEdit()
        self.pw_entry.setEchoMode(QLineEdit.Password)
        self.pw_entry.setStyleSheet("background:#071107; color:#caffd6;")
        side_layout.addWidget(self.pw_entry)

        # show/hide toggle
        self.show_btn = QPushButton("Show")
        self.show_btn.setCheckable(True)
        self.show_btn.setStyleSheet("background:#092409; color:#bfffc9;")
        self.show_btn.toggled.connect(self.toggle_password)
        side_layout.addWidget(self.show_btn)

        side_layout.addSpacing(8)

        # action buttons in sidebar
        encrypt_btn = QPushButton("Encrypt")
        encrypt_btn.setStyleSheet("background:#005500; color:#eaffd8")
        encrypt_btn.clicked.connect(self.on_encrypt)
        side_layout.addWidget(encrypt_btn)

        decrypt_btn = QPushButton("Decrypt")
        decrypt_btn.setStyleSheet("background:#550000; color:#ffdede")
        decrypt_btn.clicked.connect(self.on_decrypt)
        side_layout.addWidget(decrypt_btn)

        # settings & about
        side_layout.addStretch()
        settings_btn = QPushButton("Settings")
        settings_btn.setStyleSheet("background:#173217; color:#bfffc9;")
        settings_btn.clicked.connect(self.open_settings)
        side_layout.addWidget(settings_btn)

        about_btn = QPushButton("About")
        about_btn.setStyleSheet("background:#173217; color:#bfffc9;")
        about_btn.clicked.connect(self.show_about)
        side_layout.addWidget(about_btn)

        # Right content (console + progress + status)
        right_frame = QFrame()
        right_frame.setStyleSheet("background:#050505; border-radius:4px;")
        right_layout = QVBoxLayout(right_frame)
        right_layout.setContentsMargins(12,12,12,12)
        right_layout.setSpacing(8)

        # headline
        head = QLabel("Console")
        head.setStyleSheet("color:#00ff88;")
        head.setFont(QFont("Consolas", 12, QFont.Bold))
        right_layout.addWidget(head)

        # console text area
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setStyleSheet("background:#010A01; color:#9fffbf; font-family: Consolas;")
        self.console.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        right_layout.addWidget(self.console)

        # progress bar and status
        bottom_row = QHBoxLayout()
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setStyleSheet("QProgressBar { background: #111; color: #00ff88; } QProgressBar::chunk { background: #00ff66; }")
        bottom_row.addWidget(self.progress)

        self.status_label = QLabel("Idle")
        self.status_label.setStyleSheet("color:#bfffc9;")
        bottom_row.addWidget(self.status_label)

        right_layout.addLayout(bottom_row)

        # put frames in main layout
        hbox.addWidget(sidebar)
        hbox.addWidget(right_frame, 1)

        # initial log
        self.log("Ready — select a file and enter a password.")

        # store worker refs to prevent GC
        self._current_worker = None

    # ------------------------
    # Utilities & UI helpers
    # ------------------------
    def log(self, message: str):
        self.console.append(f"> {message}")
        # auto-scroll
        self.console.verticalScrollBar().setValue(self.console.verticalScrollBar().maximum())

    def browse_file(self):
        file = QFileDialog.getOpenFileName(self, "Select file", os.path.expanduser("~"))[0]
        if file:
            self.file_entry.setText(file)
            self.log(f"Selected: {file}")

    def toggle_password(self, checked):
        if checked:
            self.pw_entry.setEchoMode(QLineEdit.Normal)
            self.show_btn.setText("Hide")
        else:
            self.pw_entry.setEchoMode(QLineEdit.Password)
            self.show_btn.setText("Show")

    def open_settings(self):
        dlg = SettingsDialog(self, self.pbkdf2_iters, self.chunk_size // 1024)
        if dlg.exec():
            iters, chunk_kb = dlg.values()
            self.pbkdf2_iters = iters
            self.chunk_size = chunk_kb * 1024
            self.log(f"Settings updated: PBKDF2={iters}, Chunk={chunk_kb}KB")

    def show_about(self):
        QMessageBox.information(self, "About ShadowCrypt Pro",
                                "ShadowCrypt Pro\nAES-GCM + PBKDF2\nBuilt with PySide6\nAuthor: Ankit\nFor demo / academic use")

    # ------------------------
    # Encrypt / Decrypt actions
    # ------------------------
    def on_encrypt(self):
        infile = self.file_entry.text().strip()
        password = self.pw_entry.text()
        if not infile or not os.path.isfile(infile):
            QMessageBox.warning(self, "Input missing", "Please select a valid file to encrypt.")
            return
        if not password:
            QMessageBox.warning(self, "Input missing", "Please enter a password.")
            return
        outfile = infile + ".enc"
        # disable UI actions while running
        self._start_worker(EncryptWorker(infile, outfile, password, self.pbkdf2_iters, self.chunk_size))

    def on_decrypt(self):
        infile = self.file_entry.text().strip()
        password = self.pw_entry.text()
        if not infile or not os.path.isfile(infile):
            QMessageBox.warning(self, "Input missing", "Please select a valid encrypted file (.enc).")
            return
        if not password:
            QMessageBox.warning(self, "Input missing", "Please enter a password.")
            return
        # create decent default output filename preserving extension if present
        if infile.endswith(".enc"):
            base = infile[:-4]
            # try to keep original extension if any
            stem, ext = os.path.splitext(base)
            outname = f"{stem}_decrypted{ext}"
        else:
            outname = infile + "_decrypted"
        self._start_worker(DecryptWorker(infile, outname, password, self.pbkdf2_iters, self.chunk_size))

    def _start_worker(self, worker):
        # ensure only one worker runs
        if self._current_worker and self._current_worker.isRunning():
            QMessageBox.information(self, "Busy", "Another operation is in progress. Please wait.")
            return

        self.progress.setValue(0)
        self.status_label.setText("Running...")
        self._current_worker = worker

        # connect signals
        worker.signals.progress.connect(self.progress.setValue)
        worker.signals.log.connect(self.log)
        worker.signals.finished.connect(self._worker_finished)

        # start
        worker.start()

    def _worker_finished(self, success: bool, info: str):
        if success:
            self.log(f"Operation done: {info}")
            QMessageBox.information(self, "Success", info)
        else:
            self.log(f"Operation failed: {info}")
            QMessageBox.critical(self, "Error", f"Operation failed:\n{info}")
        self.status_label.setText("Idle")
        self.progress.setValue(0)
        # worker thread will finish; keep ref until done
        self._current_worker = None


# ----------------------
# Run
# ----------------------
def main():
    app = QApplication(sys.argv)
    # set application-wide font for better alignment
    app.setFont(QFont("Consolas", 10))
    win = MainWindow()
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
