"""
Online Exam System
Author: Ziad Sayed Ahmed (Zico)
Contact: z.hamzawyyy@gmail.com

A desktop exam platform for students and administrators, built with
CustomTkinter.

Admin can:
  - Add, edit, and delete student accounts
  - Create multiple exams, edit exam settings (title/duration/pass mark)
  - Add, edit, and delete questions inside each exam
  - View every result, with students scoring under 50% flagged for
    attention

Students can:
  - Register their own account
  - Take any available exam (fullscreen, optionally camera-monitored,
    consent required first)
  - See their own result history, with a clear notice when a score
    needs improvement

Security: passwords are never stored in plain text (PBKDF2-SHA256 with a
random per-user salt), there is no hardcoded admin account (a first-run
wizard creates one), and repeated failed logins are throttled.

Proctoring honesty note: fullscreen + a local webcam preview is a
reasonable classroom-level deterrent, not tamper-proof lockdown security.
No video is recorded or saved to disk.
"""

import json
import os
import hmac
import hashlib
import secrets
import time
from datetime import datetime

import customtkinter as ctk
from tkinter import messagebox

try:
    import cv2
    CV2_AVAILABLE = True
except ImportError:
    CV2_AVAILABLE = False

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False


# --------------------------------------------------------------------------- #
# Paths / persistence
# --------------------------------------------------------------------------- #

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(APP_DIR, "data")
USERS_FILE = os.path.join(DATA_DIR, "users.json")
EXAMS_FILE = os.path.join(DATA_DIR, "exams.json")
RESULTS_FILE = os.path.join(DATA_DIR, "results.json")
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")

DEFAULT_SETTINGS = {
    "appearance_mode": "Dark",
    "accent": "blue",
    "proctoring_enabled": True,
}

PASS_ALERT_THRESHOLD = 0.5  # scores below 50% are flagged for attention

ACCENTS = {
    "blue":   {"fg": "#2f7bff", "hover": "#255fcc"},
    "green":  {"fg": "#2ecc71", "hover": "#27ae60"},
    "purple": {"fg": "#8e5cf7", "hover": "#6f3fd9"},
    "orange": {"fg": "#ff9f43", "hover": "#e07b18"},
    "red":    {"fg": "#e74c3c", "hover": "#c0392b"},
}

DEFAULT_QUESTIONS = [
    {"question": "What is the keyword used to define a function in Python?",
     "options": ["def", "function", "define", "func"], "answer": "A"},
    {"question": "Which of these data types is mutable?",
     "options": ["Tuple", "List", "String", "Integer"], "answer": "B"},
    {"question": "Which method converts a string to uppercase in Python?",
     "options": ["upper()", "uppercase()", "toUpperCase()", "capitalize()"], "answer": "A"},
    {"question": "What is the output of print(2 ** 3)?",
     "options": ["6", "8", "9", "12"], "answer": "B"},
    {"question": "How do you write a single-line comment in Python?",
     "options": ["#", "//", "/*", "<!--"], "answer": "A"},
]

DEFAULT_EXAMS = [
    {"id": 1, "title": "Python Basics", "duration_minutes": 15,
     "pass_ratio": 0.6, "questions": DEFAULT_QUESTIONS}
]


def ensure_data_files():
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.isfile(USERS_FILE):
        _write_json(USERS_FILE, [])
    if not os.path.isfile(EXAMS_FILE):
        _write_json(EXAMS_FILE, DEFAULT_EXAMS)
    if not os.path.isfile(RESULTS_FILE):
        _write_json(RESULTS_FILE, [])
    if not os.path.isfile(SETTINGS_FILE):
        _write_json(SETTINGS_FILE, DEFAULT_SETTINGS)


def _read_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def _write_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


# --------------------------------------------------------------------------- #
# Security helpers
# --------------------------------------------------------------------------- #

def hash_password(password: str, salt: str = None):
    if salt is None:
        salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                  salt.encode("utf-8"), 100_000)
    return digest.hex(), salt


def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    computed, _ = hash_password(password, salt)
    return hmac.compare_digest(computed, expected_hash)


def valid_email(email: str) -> bool:
    return "@" in email and "." in email.split("@")[-1] and len(email) <= 100


# --------------------------------------------------------------------------- #
# Data access layer
# --------------------------------------------------------------------------- #

class Store:
    def __init__(self):
        self.users = _read_json(USERS_FILE, [])
        self.exams = _read_json(EXAMS_FILE, DEFAULT_EXAMS)
        self.results = _read_json(RESULTS_FILE, [])
        self.settings = {**DEFAULT_SETTINGS, **_read_json(SETTINGS_FILE, {})}
        self.failed_attempts = {}

    # ---- persistence ----
    def save_users(self):
        _write_json(USERS_FILE, self.users)

    def save_exams(self):
        _write_json(EXAMS_FILE, self.exams)

    def save_results(self):
        _write_json(RESULTS_FILE, self.results)

    def save_settings(self):
        _write_json(SETTINGS_FILE, self.settings)

    # ---- users ----
    def has_admin(self):
        return any(u["role"] == "admin" for u in self.users)

    def find_user(self, email):
        email = email.strip().lower()
        for u in self.users:
            if u["email"].lower() == email:
                return u
        return None

    def find_user_by_id(self, user_id):
        for u in self.users:
            if u["id"] == user_id:
                return u
        return None

    def create_user(self, name, email, password, role="student"):
        pw_hash, salt = hash_password(password)
        user = {
            "id": (max([u["id"] for u in self.users], default=0) + 1),
            "name": name.strip(),
            "email": email.strip().lower(),
            "password_hash": pw_hash,
            "salt": salt,
            "role": role,
            "created_at": datetime.now().isoformat(timespec="seconds"),
        }
        self.users.append(user)
        self.save_users()
        return user

    def delete_user(self, user_id):
        self.users = [u for u in self.users if u["id"] != user_id]
        self.save_users()

    def update_user(self, user_id, name=None, email=None, password=None):
        for u in self.users:
            if u["id"] == user_id:
                if name:
                    u["name"] = name.strip()
                if email:
                    u["email"] = email.strip().lower()
                if password:
                    u["password_hash"], u["salt"] = hash_password(password)
                self.save_users()
                return u
        return None

    # ---- login throttling ----
    def register_failed_login(self, email):
        count, _ = self.failed_attempts.get(email, (0, 0))
        count += 1
        locked_until = time.time() + 30 if count >= 5 else 0
        self.failed_attempts[email] = (count, locked_until)

    def clear_failed_logins(self, email):
        self.failed_attempts.pop(email, None)

    def is_locked(self, email):
        count, locked_until = self.failed_attempts.get(email, (0, 0))
        if locked_until and time.time() < locked_until:
            return True, int(locked_until - time.time())
        return False, 0

    def authenticate(self, email, password):
        locked, remaining = self.is_locked(email)
        if locked:
            return None, f"Too many failed attempts. Try again in {remaining}s."
        user = self.find_user(email)
        if not user or not verify_password(password, user["salt"], user["password_hash"]):
            self.register_failed_login(email)
            return None, "Invalid email or password."
        self.clear_failed_logins(email)
        return user, None

    # ---- exams ----
    def find_exam(self, exam_id):
        for e in self.exams:
            if e["id"] == exam_id:
                return e
        return None

    def create_exam(self, title, duration_minutes, pass_ratio):
        exam = {
            "id": (max([e["id"] for e in self.exams], default=0) + 1),
            "title": title.strip(),
            "duration_minutes": duration_minutes,
            "pass_ratio": pass_ratio,
            "questions": [],
        }
        self.exams.append(exam)
        self.save_exams()
        return exam

    def update_exam(self, exam_id, title=None, duration_minutes=None, pass_ratio=None):
        exam = self.find_exam(exam_id)
        if not exam:
            return None
        if title:
            exam["title"] = title.strip()
        if duration_minutes is not None:
            exam["duration_minutes"] = duration_minutes
        if pass_ratio is not None:
            exam["pass_ratio"] = pass_ratio
        self.save_exams()
        return exam

    def delete_exam(self, exam_id):
        self.exams = [e for e in self.exams if e["id"] != exam_id]
        self.save_exams()

    def add_question(self, exam_id, question, options, answer):
        exam = self.find_exam(exam_id)
        if not exam:
            return
        exam["questions"].append({"question": question, "options": options, "answer": answer})
        self.save_exams()

    def update_question(self, exam_id, q_index, question, options, answer):
        exam = self.find_exam(exam_id)
        if not exam or not (0 <= q_index < len(exam["questions"])):
            return
        exam["questions"][q_index] = {"question": question, "options": options, "answer": answer}
        self.save_exams()

    def delete_question(self, exam_id, q_index):
        exam = self.find_exam(exam_id)
        if not exam or not (0 <= q_index < len(exam["questions"])):
            return
        exam["questions"].pop(q_index)
        self.save_exams()

    # ---- results ----
    def add_result(self, record):
        self.results.append(record)
        self.save_results()

    def results_for(self, email):
        return [r for r in self.results if r["email"] == email]


STORE = Store()


# --------------------------------------------------------------------------- #
# Reusable UI helpers
# --------------------------------------------------------------------------- #

def accent(app):
    return ACCENTS.get(app.settings["accent"], ACCENTS["blue"])


def accent_button(app, master, **kwargs):
    colors = accent(app)
    defaults = dict(fg_color=colors["fg"], hover_color=colors["hover"],
                     font=("Segoe UI", 14, "bold"), corner_radius=10)
    defaults.update(kwargs)
    return ctk.CTkButton(master, **defaults)


def is_low_score(score, total):
    if total == 0:
        return False
    return (score / total) < PASS_ALERT_THRESHOLD


class CameraPanel(ctk.CTkFrame):
    """Live local webcam preview. Nothing is recorded or saved."""

    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.label = ctk.CTkLabel(self, text="", width=220, height=165)
        self.label.pack(padx=6, pady=6)
        self.status = ctk.CTkLabel(self, text="Monitoring active", font=("Segoe UI", 11),
                                    text_color="#8fe3a0")
        self.status.pack(pady=(0, 6))
        self.cap = None
        self._running = False

        if CV2_AVAILABLE and PIL_AVAILABLE:
            try:
                self.cap = cv2.VideoCapture(0)
                if not self.cap.isOpened():
                    self.cap = None
            except Exception:
                self.cap = None

        if self.cap is None:
            self.status.configure(text="Camera unavailable", text_color="#e78a8a")

    def start(self):
        if self.cap is not None:
            self._running = True
            self._update_frame()

    def stop(self):
        self._running = False
        if self.cap is not None:
            self.cap.release()
            self.cap = None

    def _update_frame(self):
        if not self._running or self.cap is None:
            return
        ok, frame = self.cap.read()
        if ok:
            frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            frame = cv2.resize(frame, (220, 165))
            img = Image.fromarray(frame)
            ctk_img = ctk.CTkImage(light_image=img, dark_image=img, size=(220, 165))
            self.label.configure(image=ctk_img, text="")
            self.label.image = ctk_img
        self.after(200, self._update_frame)


# --------------------------------------------------------------------------- #
# Modal dialogs
# --------------------------------------------------------------------------- #

class StudentDialog(ctk.CTkToplevel):
    """Add or edit a student. Pass existing_user=None to add."""

    def __init__(self, app, existing_user, on_saved):
        super().__init__(app)
        self.app = app
        self.existing_user = existing_user
        self.on_saved = on_saved
        self.title("Edit Student" if existing_user else "Add Student")
        self.geometry("360x360")
        self.grab_set()

        ctk.CTkLabel(self, text="Edit Student" if existing_user else "Add Student",
                     font=("Segoe UI", 18, "bold")).pack(pady=(24, 16))

        self.name_entry = ctk.CTkEntry(self, placeholder_text="Full name", width=280)
        self.name_entry.pack(pady=6)
        self.email_entry = ctk.CTkEntry(self, placeholder_text="Email", width=280)
        self.email_entry.pack(pady=6)
        pw_placeholder = "New password (leave blank to keep current)" if existing_user else "Password (min 8 characters)"
        self.pw_entry = ctk.CTkEntry(self, placeholder_text=pw_placeholder, show="*", width=280)
        self.pw_entry.pack(pady=6)

        if existing_user:
            self.name_entry.insert(0, existing_user["name"])
            self.email_entry.insert(0, existing_user["email"])

        self.error_label = ctk.CTkLabel(self, text="", text_color="#e78a8a", font=("Segoe UI", 11))
        self.error_label.pack(pady=(6, 0))

        accent_button(self.app, self, text="Save", command=self._save, width=280).pack(pady=18)

    def _save(self):
        name = self.name_entry.get().strip()
        email = self.email_entry.get().strip()
        pw = self.pw_entry.get()

        if not name or not valid_email(email):
            self.error_label.configure(text="Enter a valid name and email.")
            return

        existing_with_email = self.app.store.find_user(email)
        if existing_with_email and (not self.existing_user or existing_with_email["id"] != self.existing_user["id"]):
            self.error_label.configure(text="Another account already uses this email.")
            return

        if self.existing_user:
            if pw and len(pw) < 8:
                self.error_label.configure(text="Password must be at least 8 characters.")
                return
            self.app.store.update_user(self.existing_user["id"], name=name, email=email,
                                        password=pw if pw else None)
        else:
            if len(pw) < 8:
                self.error_label.configure(text="Password must be at least 8 characters.")
                return
            self.app.store.create_user(name, email, pw, role="student")

        self.destroy()
        self.on_saved()


class ExamDialog(ctk.CTkToplevel):
    """Add or edit an exam's title/duration/pass mark."""

    def __init__(self, app, existing_exam, on_saved):
        super().__init__(app)
        self.app = app
        self.existing_exam = existing_exam
        self.on_saved = on_saved
        self.title("Edit Exam" if existing_exam else "Add Exam")
        self.geometry("360x360")
        self.grab_set()

        ctk.CTkLabel(self, text="Edit Exam" if existing_exam else "Add Exam",
                     font=("Segoe UI", 18, "bold")).pack(pady=(24, 16))

        self.title_entry = ctk.CTkEntry(self, placeholder_text="Exam title", width=280)
        self.title_entry.pack(pady=6)
        self.duration_entry = ctk.CTkEntry(self, placeholder_text="Duration (minutes)", width=280)
        self.duration_entry.pack(pady=6)
        self.pass_entry = ctk.CTkEntry(self, placeholder_text="Pass mark, e.g. 50 for 50%", width=280)
        self.pass_entry.pack(pady=6)

        if existing_exam:
            self.title_entry.insert(0, existing_exam["title"])
            self.duration_entry.insert(0, str(existing_exam["duration_minutes"]))
            self.pass_entry.insert(0, str(int(existing_exam["pass_ratio"] * 100)))
        else:
            self.duration_entry.insert(0, "15")
            self.pass_entry.insert(0, "60")

        self.error_label = ctk.CTkLabel(self, text="", text_color="#e78a8a", font=("Segoe UI", 11))
        self.error_label.pack(pady=(6, 0))

        accent_button(self.app, self, text="Save", command=self._save, width=280).pack(pady=18)

    def _save(self):
        title = self.title_entry.get().strip()
        if not title:
            self.error_label.configure(text="Enter an exam title.")
            return
        try:
            duration = max(1, int(self.duration_entry.get()))
            pass_pct = min(100, max(1, int(self.pass_entry.get())))
        except ValueError:
            self.error_label.configure(text="Duration and pass mark must be whole numbers.")
            return

        pass_ratio = pass_pct / 100
        if self.existing_exam:
            self.app.store.update_exam(self.existing_exam["id"], title=title,
                                        duration_minutes=duration, pass_ratio=pass_ratio)
        else:
            self.app.store.create_exam(title, duration, pass_ratio)

        self.destroy()
        self.on_saved()


class QuestionDialog(ctk.CTkToplevel):
    """Add or edit a single question within an exam."""

    def __init__(self, app, exam_id, q_index, existing_question, on_saved):
        super().__init__(app)
        self.app = app
        self.exam_id = exam_id
        self.q_index = q_index
        self.on_saved = on_saved
        self.title("Edit Question" if existing_question else "Add Question")
        self.geometry("460x420")
        self.grab_set()

        ctk.CTkLabel(self, text="Edit Question" if existing_question else "Add Question",
                     font=("Segoe UI", 18, "bold")).pack(pady=(24, 16))

        self.q_entry = ctk.CTkEntry(self, placeholder_text="Question text", width=380)
        self.q_entry.pack(pady=6)

        self.opt_entries = []
        for i in range(4):
            e = ctk.CTkEntry(self, placeholder_text=f"Option {chr(65+i)}", width=380)
            e.pack(pady=4)
            self.opt_entries.append(e)

        self.ans_menu = ctk.CTkOptionMenu(self, values=["A", "B", "C", "D"], width=100)
        self.ans_menu.pack(pady=12)

        if existing_question:
            self.q_entry.insert(0, existing_question["question"])
            for e, opt in zip(self.opt_entries, existing_question["options"]):
                e.insert(0, opt)
            self.ans_menu.set(existing_question["answer"])

        self.error_label = ctk.CTkLabel(self, text="", text_color="#e78a8a", font=("Segoe UI", 11))
        self.error_label.pack(pady=(0, 6))

        accent_button(self.app, self, text="Save", command=self._save, width=280).pack(pady=10)

    def _save(self):
        text = self.q_entry.get().strip()
        options = [e.get().strip() for e in self.opt_entries]
        if not text or any(not o for o in options):
            self.error_label.configure(text="Fill in the question and all four options.")
            return
        answer = self.ans_menu.get()

        if self.q_index is None:
            self.app.store.add_question(self.exam_id, text, options, answer)
        else:
            self.app.store.update_question(self.exam_id, self.q_index, text, options, answer)

        self.destroy()
        self.on_saved()


# --------------------------------------------------------------------------- #
# Main application
# --------------------------------------------------------------------------- #

class ExamApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.store = STORE
        self.settings = self.store.settings
        self.current_user = None

        ctk.set_appearance_mode(self.settings.get("appearance_mode", "Dark"))
        ctk.set_default_color_theme("blue")

        self.title("Online Exam System - Ziad Sayed Ahmed")
        self.geometry("1120x740")
        self.minsize(940, 640)

        self.container = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.container.pack(fill="both", expand=True)

        if not self.store.has_admin():
            self.show_setup_wizard()
        else:
            self.show_login()

    def _clear(self):
        for widget in self.container.winfo_children():
            widget.destroy()

    # ---------------- first-run setup ----------------
    def show_setup_wizard(self):
        self._clear()
        card = ctk.CTkFrame(self.container, corner_radius=18, width=420)
        card.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(card, text="Welcome - Initial Setup", font=("Segoe UI", 22, "bold")).pack(pady=(30, 4), padx=40)
        ctk.CTkLabel(card, text="No administrator account exists yet.\nCreate one now (it will be stored securely, hashed).",
                     font=("Segoe UI", 12), justify="center").pack(pady=(0, 20), padx=40)

        name_entry = ctk.CTkEntry(card, placeholder_text="Admin full name", width=280)
        name_entry.pack(pady=6)
        email_entry = ctk.CTkEntry(card, placeholder_text="Admin email", width=280)
        email_entry.pack(pady=6)
        pw_entry = ctk.CTkEntry(card, placeholder_text="Password (min 8 characters)", show="*", width=280)
        pw_entry.pack(pady=6)
        pw2_entry = ctk.CTkEntry(card, placeholder_text="Confirm password", show="*", width=280)
        pw2_entry.pack(pady=6)

        error_label = ctk.CTkLabel(card, text="", text_color="#e78a8a", font=("Segoe UI", 11))
        error_label.pack(pady=(4, 0))

        def create_admin():
            name = name_entry.get().strip()
            email = email_entry.get().strip()
            pw = pw_entry.get()
            pw2 = pw2_entry.get()
            if not name or not valid_email(email):
                error_label.configure(text="Please enter a valid name and email.")
                return
            if len(pw) < 8:
                error_label.configure(text="Password must be at least 8 characters.")
                return
            if pw != pw2:
                error_label.configure(text="Passwords do not match.")
                return
            self.store.create_user(name, email, pw, role="admin")
            messagebox.showinfo("Setup complete", "Administrator account created. Please log in.")
            self.show_login()

        accent_button(self, card, text="Create Admin Account", command=create_admin, width=280).pack(pady=(14, 10))
        ctk.CTkLabel(card, text="Online Exam System - built by Ziad Sayed Ahmed",
                     font=("Segoe UI", 10), text_color="gray60").pack(pady=(6, 24))

    # ---------------- login ----------------
    def show_login(self):
        self._clear()
        self.current_user = None

        card = ctk.CTkFrame(self.container, corner_radius=18)
        card.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(card, text="Online Exam System", font=("Segoe UI", 26, "bold")).pack(pady=(36, 2), padx=60)
        ctk.CTkLabel(card, text="Sign in to continue", font=("Segoe UI", 13), text_color="gray60").pack(pady=(0, 20))

        email_entry = ctk.CTkEntry(card, placeholder_text="Email", width=300)
        email_entry.pack(pady=8)
        pw_entry = ctk.CTkEntry(card, placeholder_text="Password", show="*", width=300)
        pw_entry.pack(pady=8)

        error_label = ctk.CTkLabel(card, text="", text_color="#e78a8a", font=("Segoe UI", 11))
        error_label.pack(pady=(4, 0))

        def do_login():
            email = email_entry.get().strip()
            pw = pw_entry.get()
            user, err = self.store.authenticate(email, pw)
            if err:
                error_label.configure(text=err)
                return
            self.current_user = user
            if user["role"] == "admin":
                self.show_admin_students()
            else:
                self.show_student_home()

        accent_button(self, card, text="Log In", command=do_login, width=300).pack(pady=18)

        signup_row = ctk.CTkFrame(card, fg_color="transparent")
        signup_row.pack(pady=(0, 10))
        ctk.CTkLabel(signup_row, text="New student?", font=("Segoe UI", 11)).pack(side="left", padx=(0, 6))
        ctk.CTkButton(signup_row, text="Create an account", fg_color="transparent",
                      hover=False, text_color=accent(self)["fg"],
                      command=self.show_signup, width=1).pack(side="left")

        ctk.CTkLabel(card, text="Online Exam System - built by Ziad Sayed Ahmed",
                     font=("Segoe UI", 10), text_color="gray60").pack(pady=(4, 30))

    def show_signup(self):
        self._clear()
        card = ctk.CTkFrame(self.container, corner_radius=18)
        card.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(card, text="Create Student Account", font=("Segoe UI", 22, "bold")).pack(pady=(30, 16), padx=50)
        name_entry = ctk.CTkEntry(card, placeholder_text="Full name", width=280)
        name_entry.pack(pady=6)
        email_entry = ctk.CTkEntry(card, placeholder_text="Email", width=280)
        email_entry.pack(pady=6)
        pw_entry = ctk.CTkEntry(card, placeholder_text="Password (min 8 characters)", show="*", width=280)
        pw_entry.pack(pady=6)

        error_label = ctk.CTkLabel(card, text="", text_color="#e78a8a", font=("Segoe UI", 11))
        error_label.pack(pady=(6, 0))

        def do_signup():
            name = name_entry.get().strip()
            email = email_entry.get().strip()
            pw = pw_entry.get()
            if not name or not valid_email(email):
                error_label.configure(text="Enter a valid name and email.")
                return
            if len(pw) < 8:
                error_label.configure(text="Password must be at least 8 characters.")
                return
            if self.store.find_user(email):
                error_label.configure(text="An account with this email already exists.")
                return
            self.store.create_user(name, email, pw, role="student")
            messagebox.showinfo("Account created", "You can now log in.")
            self.show_login()

        accent_button(self, card, text="Create Account", command=do_signup, width=280).pack(pady=18)
        ctk.CTkButton(card, text="Back to login", fg_color="transparent", hover=False,
                      text_color=accent(self)["fg"], command=self.show_login).pack(pady=(0, 26))

    # ---------------- shared dashboard shell ----------------
    def _admin_nav(self):
        return [
            ("Students", self.show_admin_students),
            ("Exams", self.show_admin_exams),
            ("Results", self.show_admin_results),
            ("Settings", self.show_admin_settings),
        ]

    def _student_nav(self):
        return [
            ("Available Exams", self.show_student_home),
            ("My Results", self.show_student_results),
        ]

    def _dashboard_shell(self, title, nav_items):
        self._clear()
        sidebar = ctk.CTkFrame(self.container, width=230, corner_radius=0)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        ctk.CTkLabel(sidebar, text=title, font=("Segoe UI", 18, "bold")).pack(pady=(28, 4), padx=16)
        ctk.CTkLabel(sidebar, text=self.current_user["name"], font=("Segoe UI", 12),
                     text_color="gray60").pack(pady=(0, 24), padx=16)

        for label, cmd in nav_items:
            ctk.CTkButton(sidebar, text=label, anchor="w", fg_color="transparent",
                          hover_color=("gray80", "gray25"), font=("Segoe UI", 13),
                          command=cmd).pack(fill="x", padx=14, pady=4)

        ctk.CTkButton(sidebar, text="Log Out", fg_color="#e74c3c", hover_color="#c0392b",
                      command=self.show_login).pack(side="bottom", fill="x", padx=14, pady=20)

        content_outer = ctk.CTkFrame(self.container, corner_radius=0, fg_color="transparent")
        content_outer.pack(side="right", fill="both", expand=True, padx=24, pady=24)
        return content_outer

    # ---------------- admin: students ----------------
    def show_admin_students(self):
        content = self._dashboard_shell("Admin Panel", self._admin_nav())

        header = ctk.CTkFrame(content, fg_color="transparent")
        header.pack(fill="x", pady=(0, 12))
        ctk.CTkLabel(header, text="Students", font=("Segoe UI", 20, "bold")).pack(side="left")
        accent_button(self, header, text="+ Add Student", width=150,
                      command=lambda: StudentDialog(self, None, self.show_admin_students)).pack(side="right")

        scroll = ctk.CTkScrollableFrame(content, fg_color="transparent")
        scroll.pack(fill="both", expand=True)

        students = [u for u in self.store.users if u["role"] == "student"]
        if not students:
            ctk.CTkLabel(scroll, text="No students yet. Add one, or have them register from the login screen.",
                         text_color="gray60").pack(pady=20)

        for u in students:
            row = ctk.CTkFrame(scroll, corner_radius=10)
            row.pack(fill="x", pady=4)
            ctk.CTkLabel(row, text=f"{u['name']}  -  {u['email']}", font=("Segoe UI", 13)).pack(
                side="left", padx=14, pady=10)
            ctk.CTkButton(row, text="Delete", width=80, fg_color="#e74c3c", hover_color="#c0392b",
                          command=lambda uid=u["id"]: self._delete_student(uid)).pack(side="right", padx=(0, 10))
            ctk.CTkButton(row, text="Edit", width=80,
                          command=lambda u=u: StudentDialog(self, u, self.show_admin_students)).pack(
                side="right", padx=6)

    def _delete_student(self, user_id):
        if messagebox.askyesno("Confirm", "Delete this student account? Their results will remain on record."):
            self.store.delete_user(user_id)
            self.show_admin_students()

    # ---------------- admin: exams ----------------
    def show_admin_exams(self):
        content = self._dashboard_shell("Admin Panel", self._admin_nav())

        header = ctk.CTkFrame(content, fg_color="transparent")
        header.pack(fill="x", pady=(0, 12))
        ctk.CTkLabel(header, text="Exams", font=("Segoe UI", 20, "bold")).pack(side="left")
        accent_button(self, header, text="+ Add Exam", width=150,
                      command=lambda: ExamDialog(self, None, self.show_admin_exams)).pack(side="right")

        scroll = ctk.CTkScrollableFrame(content, fg_color="transparent")
        scroll.pack(fill="both", expand=True)

        if not self.store.exams:
            ctk.CTkLabel(scroll, text="No exams yet.", text_color="gray60").pack(pady=20)

        for exam in self.store.exams:
            row = ctk.CTkFrame(scroll, corner_radius=12)
            row.pack(fill="x", pady=6)

            info = ctk.CTkFrame(row, fg_color="transparent")
            info.pack(side="left", fill="x", expand=True, padx=14, pady=12)
            ctk.CTkLabel(info, text=exam["title"], font=("Segoe UI", 15, "bold")).pack(anchor="w")
            ctk.CTkLabel(info, text=f"{len(exam['questions'])} questions  |  {exam['duration_minutes']} min  |  "
                                     f"pass mark {int(exam['pass_ratio']*100)}%",
                         font=("Segoe UI", 11), text_color="gray60").pack(anchor="w")

            btns = ctk.CTkFrame(row, fg_color="transparent")
            btns.pack(side="right", padx=10)
            ctk.CTkButton(btns, text="Delete", width=80, fg_color="#e74c3c", hover_color="#c0392b",
                          command=lambda eid=exam["id"]: self._delete_exam(eid)).pack(side="right", padx=4)
            ctk.CTkButton(btns, text="Edit", width=80,
                          command=lambda e=exam: ExamDialog(self, e, self.show_admin_exams)).pack(
                side="right", padx=4)
            accent_button(self, btns, text="Manage Questions", width=160,
                          command=lambda eid=exam["id"]: self.show_admin_exam_questions(eid)).pack(
                side="right", padx=4)

    def _delete_exam(self, exam_id):
        if messagebox.askyesno("Confirm", "Delete this exam and all of its questions?"):
            self.store.delete_exam(exam_id)
            self.show_admin_exams()

    def show_admin_exam_questions(self, exam_id):
        exam = self.store.find_exam(exam_id)
        content = self._dashboard_shell("Admin Panel", self._admin_nav())
        if not exam:
            ctk.CTkLabel(content, text="Exam not found.").pack()
            return

        top = ctk.CTkFrame(content, fg_color="transparent")
        top.pack(fill="x", pady=(0, 4))
        ctk.CTkButton(top, text="< Back to Exams", fg_color="transparent", hover_color=("gray80", "gray25"),
                      command=self.show_admin_exams, width=140).pack(side="left")

        header = ctk.CTkFrame(content, fg_color="transparent")
        header.pack(fill="x", pady=(4, 12))
        ctk.CTkLabel(header, text=f"Questions - {exam['title']}", font=("Segoe UI", 20, "bold")).pack(side="left")
        accent_button(self, header, text="+ Add Question", width=150,
                      command=lambda: QuestionDialog(self, exam_id, None, None,
                                                      lambda: self.show_admin_exam_questions(exam_id))).pack(
            side="right")

        scroll = ctk.CTkScrollableFrame(content, fg_color="transparent")
        scroll.pack(fill="both", expand=True)

        if not exam["questions"]:
            ctk.CTkLabel(scroll, text="No questions yet.", text_color="gray60").pack(pady=20)

        for idx, q in enumerate(exam["questions"]):
            row = ctk.CTkFrame(scroll, corner_radius=10)
            row.pack(fill="x", pady=4)
            summary = f"Q{idx+1}: {q['question']}  (Answer: {q['answer']})"
            ctk.CTkLabel(row, text=summary, font=("Segoe UI", 12), wraplength=560, justify="left").pack(
                side="left", padx=14, pady=10)
            ctk.CTkButton(row, text="Delete", width=80, fg_color="#e74c3c", hover_color="#c0392b",
                          command=lambda i=idx: self._delete_question(exam_id, i)).pack(side="right", padx=(0, 10))
            ctk.CTkButton(row, text="Edit", width=80,
                          command=lambda i=idx, q=q: QuestionDialog(
                              self, exam_id, i, q, lambda: self.show_admin_exam_questions(exam_id))).pack(
                side="right", padx=6)

    def _delete_question(self, exam_id, index):
        if messagebox.askyesno("Confirm", "Delete this question?"):
            self.store.delete_question(exam_id, index)
            self.show_admin_exam_questions(exam_id)

    # ---------------- admin: results ----------------
    def show_admin_results(self):
        content = self._dashboard_shell("Admin Panel", self._admin_nav())

        header = ctk.CTkFrame(content, fg_color="transparent")
        header.pack(fill="x", pady=(0, 12))
        ctk.CTkLabel(header, text="Exam Results", font=("Segoe UI", 20, "bold")).pack(side="left")

        low_scores = [r for r in self.store.results if is_low_score(r["score"], r["total"])]
        if low_scores:
            alert = ctk.CTkFrame(content, corner_radius=12, fg_color="#4a2020")
            alert.pack(fill="x", pady=(0, 14))
            ctk.CTkLabel(alert, text=f"⚠ {len(low_scores)} attempt(s) scored under 50% and need attention",
                         font=("Segoe UI", 13, "bold"), text_color="#ff9f9f").pack(padx=16, pady=12, anchor="w")

        scroll = ctk.CTkScrollableFrame(content, fg_color="transparent")
        scroll.pack(fill="both", expand=True)

        if not self.store.results:
            ctk.CTkLabel(scroll, text="No exam attempts recorded yet.", text_color="gray60").pack(pady=20)

        for r in reversed(self.store.results):
            flagged = is_low_score(r["score"], r["total"])
            row = ctk.CTkFrame(scroll, corner_radius=10,
                                fg_color="#3a2323" if flagged else None)
            row.pack(fill="x", pady=4)
            status = "PASSED" if r["passed"] else "FAILED"
            tag = "  ⚠ NEEDS ATTENTION" if flagged else ""
            text = (f"{r['name']} ({r['email']})  |  {r.get('exam_title', 'Exam')}  |  "
                    f"{r['score']}/{r['total']}  |  {status}{tag}  |  "
                    f"{r['timestamp']}  |  focus-loss: {r.get('focus_loss', 0)}")
            ctk.CTkLabel(row, text=text, font=("Segoe UI", 12), wraplength=760, justify="left",
                         text_color="#ff9f9f" if flagged else None).pack(anchor="w", padx=14, pady=10)

    # ---------------- admin: settings ----------------
    def show_admin_settings(self):
        content = self._dashboard_shell("Admin Panel", self._admin_nav())
        ctk.CTkLabel(content, text="Settings", font=("Segoe UI", 20, "bold")).pack(anchor="w", pady=(0, 16))

        ctk.CTkLabel(content, text="Appearance mode", font=("Segoe UI", 13)).pack(anchor="w")
        mode_menu = ctk.CTkOptionMenu(content, values=["Light", "Dark", "System"],
                                       command=self._change_appearance)
        mode_menu.set(self.settings.get("appearance_mode", "Dark"))
        mode_menu.pack(anchor="w", pady=(4, 16))

        ctk.CTkLabel(content, text="Accent color", font=("Segoe UI", 13)).pack(anchor="w")
        accent_row = ctk.CTkFrame(content, fg_color="transparent")
        accent_row.pack(anchor="w", pady=(4, 16))
        for name, colors in ACCENTS.items():
            ctk.CTkButton(accent_row, text="", width=32, height=32, corner_radius=16,
                          fg_color=colors["fg"], hover_color=colors["hover"],
                          command=lambda n=name: self._change_accent(n)).pack(side="left", padx=4)

        proctor_var = ctk.BooleanVar(value=self.settings.get("proctoring_enabled", True))

        def toggle_proctor():
            self.settings["proctoring_enabled"] = proctor_var.get()
            self.store.save_settings()

        ctk.CTkCheckBox(content, text="Enable fullscreen + camera monitoring during exams",
                         variable=proctor_var, command=toggle_proctor).pack(anchor="w", pady=(0, 6))
        ctk.CTkLabel(content, text="Duration and pass mark are set per exam under Exams > Edit.",
                     font=("Segoe UI", 11), text_color="gray60").pack(anchor="w")

    def _change_appearance(self, mode):
        ctk.set_appearance_mode(mode)
        self.settings["appearance_mode"] = mode
        self.store.save_settings()

    def _change_accent(self, name):
        self.settings["accent"] = name
        self.store.save_settings()
        self.show_admin_settings()

    # ---------------- student: home / available exams ----------------
    def show_student_home(self):
        content = self._dashboard_shell("Student Panel", self._student_nav())
        ctk.CTkLabel(content, text=f"Welcome, {self.current_user['name']}",
                     font=("Segoe UI", 22, "bold")).pack(anchor="w", pady=(0, 4))

        proctor_on = self.settings.get("proctoring_enabled", True)
        notice = ("Exams run in fullscreen mode with a local camera preview shown to you, and "
                   "tab-switch / focus-loss events are logged for the instructor. Nothing is "
                   "recorded to disk.") if proctor_on else "Exams do not use fullscreen lock or camera monitoring."
        ctk.CTkLabel(content, text=notice, font=("Segoe UI", 12), text_color="gray60",
                     wraplength=650, justify="left").pack(anchor="w", pady=(0, 20))

        scroll = ctk.CTkScrollableFrame(content, fg_color="transparent")
        scroll.pack(fill="both", expand=True)

        if not self.store.exams:
            ctk.CTkLabel(scroll, text="No exams are available right now.", text_color="gray60").pack(pady=20)

        for exam in self.store.exams:
            row = ctk.CTkFrame(scroll, corner_radius=12)
            row.pack(fill="x", pady=6)
            info = ctk.CTkFrame(row, fg_color="transparent")
            info.pack(side="left", fill="x", expand=True, padx=16, pady=14)
            ctk.CTkLabel(info, text=exam["title"], font=("Segoe UI", 15, "bold")).pack(anchor="w")
            ctk.CTkLabel(info, text=f"{len(exam['questions'])} questions  |  {exam['duration_minutes']} minutes",
                         font=("Segoe UI", 11), text_color="gray60").pack(anchor="w")

            def make_start(e=exam):
                return lambda: self._begin_exam_flow(e)

            accent_button(self, row, text="Start Exam", width=140,
                          command=make_start()).pack(side="right", padx=16)

    def _begin_exam_flow(self, exam):
        if not exam["questions"]:
            messagebox.showwarning("No questions", "This exam has no questions yet.")
            return
        proctor_on = self.settings.get("proctoring_enabled", True)
        if not proctor_on:
            ExamWindow(self, exam)
            return

        consent = ctk.CTkToplevel(self)
        consent.title("Consent required")
        consent.geometry("420x260")
        consent.grab_set()
        ctk.CTkLabel(consent, text="Before you begin", font=("Segoe UI", 16, "bold")).pack(pady=(24, 10), padx=24)
        ctk.CTkLabel(consent, text="This exam runs in fullscreen mode. A local camera preview will be "
                                     "shown to you while it is open, and tab-switch / focus-loss events "
                                     "are logged for your instructor. Nothing is recorded to disk.",
                     wraplength=360, justify="left", font=("Segoe UI", 12)).pack(padx=24, pady=(0, 16))
        agree_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(consent, text="I understand and consent to camera monitoring",
                         variable=agree_var).pack(padx=24, anchor="w")

        def proceed():
            if not agree_var.get():
                messagebox.showwarning("Consent required", "Please check the box to continue.")
                return
            consent.destroy()
            ExamWindow(self, exam)

        accent_button(self, consent, text="Begin Exam", command=proceed, width=200).pack(pady=18)

    # ---------------- student: results ----------------
    def show_student_results(self):
        content = self._dashboard_shell("Student Panel", self._student_nav())
        ctk.CTkLabel(content, text="My Results", font=("Segoe UI", 20, "bold")).pack(anchor="w", pady=(0, 12))
        scroll = ctk.CTkScrollableFrame(content, fg_color="transparent")
        scroll.pack(fill="both", expand=True)

        mine = self.store.results_for(self.current_user["email"])
        if not mine:
            ctk.CTkLabel(scroll, text="You haven't taken an exam yet.", text_color="gray60").pack(pady=20)

        for r in reversed(mine):
            flagged = is_low_score(r["score"], r["total"])
            row = ctk.CTkFrame(scroll, corner_radius=10, fg_color="#3a2323" if flagged else None)
            row.pack(fill="x", pady=4)
            status = "PASSED" if r["passed"] else "FAILED"
            ctk.CTkLabel(row, text=f"{r.get('exam_title', 'Exam')}  |  {r['score']}/{r['total']}  |  "
                                    f"{status}  |  {r['timestamp']}",
                         font=("Segoe UI", 13), text_color="#ff9f9f" if flagged else None).pack(
                anchor="w", padx=14, pady=(10, 2))
            if flagged:
                ctk.CTkLabel(row, text="⚠ Your score was under 50% on this exam. Consider reviewing "
                                        "this topic or reaching out to your instructor.",
                             font=("Segoe UI", 11), text_color="#ff9f9f", wraplength=600,
                             justify="left").pack(anchor="w", padx=14, pady=(0, 10))


class ExamWindow(ctk.CTkToplevel):
    def __init__(self, app: ExamApp, exam: dict):
        super().__init__(app)
        self.app = app
        self.exam = exam
        self.questions = exam["questions"]
        self.index = 0
        self.answers = [None] * len(self.questions)
        self.focus_loss_count = 0
        self.proctoring = app.settings.get("proctoring_enabled", True)

        self.title(f"Exam: {exam['title']}")
        self.protocol("WM_DELETE_WINDOW", self._attempt_exit)

        if self.proctoring:
            self.attributes("-fullscreen", True)
            self.bind("<FocusOut>", lambda e: self._on_focus_out())
        else:
            self.geometry("900x600")

        self.bind("<Escape>", lambda e: self._attempt_exit())

        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=24, pady=(20, 6))
        ctk.CTkLabel(top, text=exam["title"], font=("Segoe UI", 15, "bold")).pack(side="left")
        self.progress_label = ctk.CTkLabel(top, text="", font=("Segoe UI", 13))
        self.progress_label.pack(side="left", padx=(20, 0))
        self.timer_label = ctk.CTkLabel(top, text="", font=("Segoe UI", 13, "bold"))
        self.timer_label.pack(side="right")

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=24, pady=6)

        question_area = ctk.CTkFrame(body, corner_radius=16)
        question_area.pack(side="left", fill="both", expand=True, padx=(0, 16))

        self.question_label = ctk.CTkLabel(question_area, text="", font=("Segoe UI", 18, "bold"),
                                            wraplength=560, justify="left")
        self.question_label.pack(anchor="w", padx=24, pady=(28, 20))

        self.option_var = ctk.StringVar(value="")
        self.option_buttons = []
        for letter in ["A", "B", "C", "D"]:
            rb = ctk.CTkRadioButton(question_area, text="", variable=self.option_var, value=letter,
                                     font=("Segoe UI", 14), radiobutton_width=20, radiobutton_height=20)
            rb.pack(anchor="w", padx=32, pady=8)
            self.option_buttons.append(rb)

        nav = ctk.CTkFrame(question_area, fg_color="transparent")
        nav.pack(side="bottom", fill="x", padx=24, pady=24)
        self.prev_btn = ctk.CTkButton(nav, text="Previous", width=110, command=self._prev)
        self.prev_btn.pack(side="left")
        self.next_btn = accent_button(self.app, nav, text="Next", width=110, command=self._next)
        self.next_btn.pack(side="right")
        self.submit_btn = ctk.CTkButton(nav, text="Submit Exam", width=140, fg_color="#2ecc71",
                                        hover_color="#27ae60", command=self._submit)

        if self.proctoring:
            side = ctk.CTkFrame(body, width=250, corner_radius=16)
            side.pack(side="right", fill="y")
            side.pack_propagate(False)
            ctk.CTkLabel(side, text="Monitoring", font=("Segoe UI", 14, "bold")).pack(pady=(16, 6))
            self.camera = CameraPanel(side, fg_color="transparent")
            self.camera.pack(pady=6)
            self.camera.start()
            self.focus_label = ctk.CTkLabel(side, text="Focus-loss events: 0",
                                             font=("Segoe UI", 11), text_color="gray60")
            self.focus_label.pack(pady=(10, 0))
        else:
            self.camera = None

        self._render_question()
        self.remaining_seconds = exam.get("duration_minutes", 15) * 60
        self._tick_timer()

    def _on_focus_out(self):
        self.focus_loss_count += 1
        if hasattr(self, "focus_label"):
            self.focus_label.configure(text=f"Focus-loss events: {self.focus_loss_count}")

    def _attempt_exit(self):
        if messagebox.askyesno("Leave exam?",
                                "Leaving now will submit your exam with your current answers. Continue?"):
            self._submit()

    def _render_question(self):
        q = self.questions[self.index]
        self.progress_label.configure(text=f"Question {self.index + 1} of {len(self.questions)}")
        self.question_label.configure(text=q["question"])
        self.option_var.set(self.answers[self.index] or "")
        for letter, rb in zip(["A", "B", "C", "D"], self.option_buttons):
            opt_index = ord(letter) - ord("A")
            rb.configure(text=f"{letter}. {q['options'][opt_index]}")

        self.prev_btn.configure(state="normal" if self.index > 0 else "disabled")
        is_last = self.index == len(self.questions) - 1
        self.next_btn.pack_forget()
        self.submit_btn.pack_forget()
        if is_last:
            self.submit_btn.pack(side="right")
        else:
            self.next_btn.pack(side="right")

    def _store_answer(self):
        self.answers[self.index] = self.option_var.get() or None

    def _next(self):
        self._store_answer()
        self.index += 1
        self._render_question()

    def _prev(self):
        self._store_answer()
        self.index -= 1
        self._render_question()

    def _tick_timer(self):
        if self.remaining_seconds <= 0:
            messagebox.showinfo("Time's up", "Time is up. Submitting your exam now.")
            self._submit()
            return
        minutes, seconds = divmod(self.remaining_seconds, 60)
        self.timer_label.configure(text=f"Time remaining: {minutes:02d}:{seconds:02d}")
        self.remaining_seconds -= 1
        self.after(1000, self._tick_timer)

    def _submit(self):
        self._store_answer()
        score = 0
        for q, given in zip(self.questions, self.answers):
            if given == q["answer"]:
                score += 1
        total = len(self.questions)
        passed = score >= total * self.exam.get("pass_ratio", 0.6)

        record = {
            "name": self.app.current_user["name"],
            "email": self.app.current_user["email"],
            "exam_id": self.exam["id"],
            "exam_title": self.exam["title"],
            "score": score,
            "total": total,
            "passed": passed,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "focus_loss": self.focus_loss_count,
        }
        self.app.store.add_result(record)

        if self.camera is not None:
            self.camera.stop()
        self.destroy()

        status = "You passed." if passed else "You did not pass."
        warning = ""
        if is_low_score(score, total):
            warning = "\n\n⚠ Your score was under 50%. Consider reviewing this topic or contacting your instructor."
        messagebox.showinfo("Exam submitted", f"Score: {score}/{total}\n{status}{warning}")
        self.app.show_student_home()


if __name__ == "__main__":
    ensure_data_files()
    app = ExamApp()
    app.mainloop()