from pathlib import Path
from datetime import timedelta
import re
import logging
from collections import Counter
import os
from dotenv import load_dotenv
import time
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, abort, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user
)

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, CSRFError


# ---------------------------------------------------
# Flask Application Setup
# ---------------------------------------------------

app = Flask(__name__)

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent

DATABASE_DIR = BASE_DIR / "database"
DATABASE_DIR.mkdir(exist_ok=True)

LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

LOG_FILE = LOG_DIR / "auth.log"


# ---------------------------------------------------
# Application Configuration
# ---------------------------------------------------

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")

if not app.config["SECRET_KEY"]:
    raise RuntimeError(
        "SECRET_KEY environment variable is not set."
    )

app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"sqlite:///{DATABASE_DIR / 'users.db'}"
)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config["RATELIMIT_HEADERS_ENABLED"] = True

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Keep False for local HTTP development.
# Change to True when deployed behind HTTPS.

app.config["SESSION_COOKIE_SECURE"] = False

app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(
    minutes=30
)


# ---------------------------------------------------
# Security Configuration
# ---------------------------------------------------

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 300


# ---------------------------------------------------
# Flask Extensions
# ---------------------------------------------------

db = SQLAlchemy(app)

bcrypt = Bcrypt(app)

login_manager = LoginManager(app)

csrf = CSRFProtect(app)

login_manager.login_view = "login"

login_manager.login_message = "Please log in to access that page."


# ---------------------------------------------------
# Rate Limiter
# ---------------------------------------------------

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri="memory://"
)


# ---------------------------------------------------
# Security Logger
# ---------------------------------------------------

security_logger = logging.getLogger("security")

security_logger.setLevel(logging.INFO)

if not security_logger.handlers:

    file_handler = logging.FileHandler(LOG_FILE)

    formatter = logging.Formatter(
        "%(asctime)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    file_handler.setFormatter(formatter)

    security_logger.addHandler(file_handler)


# ---------------------------------------------------
# User Database Model
# ---------------------------------------------------

class User(UserMixin, db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    username = db.Column(
        db.String(50),
        unique=True,
        nullable=False
    )

    email = db.Column(
        db.String(120),
        unique=True,
        nullable=False
    )

    password_hash = db.Column(
        db.String(128),
        nullable=False
    )

    role = db.Column(
        db.String(20),
        default="user",
        nullable=False
    )

    failed_attempts = db.Column(
        db.Integer,
        default=0,
        nullable=False
    )

    locked_until = db.Column(
        db.Integer,
        nullable=True
    )


# ---------------------------------------------------
# Flask-Login User Loader
# ---------------------------------------------------

@login_manager.user_loader
def load_user(user_id):

    return db.session.get(
        User,
        int(user_id)
    )


# ---------------------------------------------------
# Security Event Logger
# ---------------------------------------------------

def log_security_event(event, username="unknown"):

    safe_username = (
        str(username)
        .replace("\n", "")
        .replace("\r", "")
    )

    ip_address = request.remote_addr or "unknown"

    security_logger.info(
        "%s user=%s ip=%s",
        event,
        safe_username,
        ip_address
    )

# ---------------------------------------------------
# Security Dashboard Log Analysis
# ---------------------------------------------------

def get_security_dashboard_data():

    event_counts = Counter()

    recent_events = []

    if not LOG_FILE.exists():

        return {
            "successful_logins": 0,
            "failed_logins": 0,
            "accounts_locked": 0,
            "unauthorized_access": 0,
            "csrf_blocked": 0,
            "rate_limits": 0,
            "admin_access": 0
        }, []


    event_pattern = re.compile(
        r"^"
        r"(?P<timestamp>\d{4}-\d{2}-\d{2} "
        r"\d{2}:\d{2}:\d{2}) "
        r"(?P<event>[A-Z_]+) "
        r"user=(?P<username>\S+) "
        r"ip=(?P<ip>\S+)"
        r"$"
    )


    with open(
        LOG_FILE,
        "r",
        encoding="utf-8"
    ) as log_file:

        for line in log_file:

            line = line.strip()

            if not line:
                continue


            match = event_pattern.match(line)

            if not match:
                continue


            event_data = {
                "timestamp": match.group("timestamp"),
                "event": match.group("event"),
                "username": match.group("username"),
                "ip": match.group("ip")
            }


            event_counts[
                event_data["event"]
            ] += 1


            recent_events.append(
                event_data
            )


    # Only show the 10 newest events

    recent_events = recent_events[-10:]

    recent_events.reverse()


    stats = {

        "successful_logins":
            event_counts["LOGIN_SUCCESS"],

        "failed_logins":
            event_counts["LOGIN_FAILED"],

        "accounts_locked":
            event_counts["ACCOUNT_LOCKED"],

        "unauthorized_access":
            (
                event_counts["UNAUTHORIZED_ACCESS"]
                +
                event_counts[
                    "UNAUTHORIZED_ADMIN_ACCESS"
                ]
            ),

        "csrf_blocked":
            event_counts["CSRF_BLOCKED"],

        "rate_limits":
            event_counts["RATE_LIMIT_EXCEEDED"],

        "admin_access":
            event_counts["ADMIN_ACCESS"]
    }


    return stats, recent_events


# ---------------------------------------------------
# Password Security Policy
# ---------------------------------------------------

def validate_password(password):

    errors = []

    if len(password) < 10:
        errors.append(
            "Password must be at least 10 characters long."
        )

    if not re.search(r"[A-Z]", password):
        errors.append(
            "Password must contain at least one uppercase letter."
        )

    if not re.search(r"[a-z]", password):
        errors.append(
            "Password must contain at least one lowercase letter."
        )

    if not re.search(r"\d", password):
        errors.append(
            "Password must contain at least one number."
        )

    if not re.search(
        r"[!@#$%^&*(),.?\":{}|<>]",
        password
    ):
        errors.append(
            "Password must contain at least one special character."
        )

    return errors

def admin_required(function):

    @wraps(function)
    def decorated_function(*args, **kwargs):

        if not current_user.is_authenticated:

            return login_manager.unauthorized()

        if current_user.role != "admin":

            log_security_event(
                "UNAUTHORIZED_ADMIN_ACCESS",
                current_user.username
            )

            abort(403)

        return function(*args, **kwargs)

    return decorated_function
# ---------------------------------------------------
# Unauthorized Access Handler
# ---------------------------------------------------

@login_manager.unauthorized_handler
def unauthorized():

    log_security_event(
        "UNAUTHORIZED_ACCESS"
    )

    flash(
        "Please log in to access that page.",
        "error"
    )

    return redirect(
        url_for("login")
    )


# ---------------------------------------------------
# Rate Limit Handler
# ---------------------------------------------------

@app.errorhandler(429)
def rate_limit_exceeded(error):

    log_security_event(
        "RATE_LIMIT_EXCEEDED"
    )

    return render_template(
        "rate_limit.html"
    ), 429

@app.errorhandler(CSRFError)
def handle_csrf_error(error):

    log_security_event(
        "CSRF_BLOCKED"
    )

    return render_template(
        "csrf_error.html",
        reason=error.description
    ), 400

# ---------------------------------------------------
# Home
# ---------------------------------------------------

@app.route("/")
def home():

    return render_template(
        "home.html"
    )


# ---------------------------------------------------
# Registration
# ---------------------------------------------------

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if current_user.is_authenticated:

        return redirect(
            url_for("dashboard")
        )

    if request.method == "POST":

        username = request.form["username"].strip()

        email = request.form["email"].strip()

        password = request.form["password"]

        confirm_password = request.form["confirm_password"]


        if password != confirm_password:

            flash(
                "Passwords do not match.",
                "error"
            )

            return redirect(
                url_for("register")
            )


        password_errors = validate_password(password)

        if password_errors:

            for error in password_errors:

                flash(
                    error,
                    "error"
                )

            return redirect(
                url_for("register")
            )


        existing_user = (
            User.query
            .filter_by(username=username)
            .first()
        )

        if existing_user:

            flash(
                "Username already exists.",
                "error"
            )

            return redirect(
                url_for("register")
            )


        existing_email = (
            User.query
            .filter_by(email=email)
            .first()
        )

        if existing_email:

            flash(
                "Email already registered.",
                "error"
            )

            return redirect(
                url_for("register")
            )


        hashed_password = (
            bcrypt
            .generate_password_hash(password)
            .decode("utf-8")
        )


        new_user = User(
            username=username,
            email=email,
            password_hash=hashed_password,
            role="user",
            failed_attempts=0,
            locked_until=None
        )


        db.session.add(new_user)

        db.session.commit()


        log_security_event(
            "ACCOUNT_CREATED",
            username
        )


        flash(
            "Account created successfully. You can now log in.",
            "success"
        )

        return redirect(
            url_for("login")
        )


    return render_template(
        "register.html"
    )




# ---------------------------------------------------
# Login
# ---------------------------------------------------

@app.route(
    "/login",
    methods=["GET", "POST"]
)
@limiter.limit(
    "8 per minute",
    methods=["POST"]
)
def login():

    if current_user.is_authenticated:
        return redirect(
            url_for("dashboard")
        )

    if request.method == "POST":

        username = request.form["username"].strip()
        password = request.form["password"]

        user = (
            User.query
            .filter_by(username=username)
            .first()
        )


        # -------------------------------------------
        # Check Account Lock
        # -------------------------------------------

        if user and user.locked_until:

            current_time = int(time.time())

            if current_time < user.locked_until:

                remaining_seconds = (
                    user.locked_until
                    - current_time
                )

                flash(
                    f"Account temporarily locked. "
                    f"Try again in {remaining_seconds} seconds.",
                    "error"
                )

                log_security_event(
                    "LOCKED_LOGIN_ATTEMPT",
                    username
                )

                return render_template(
                    "login.html"
                )

            else:

                user.failed_attempts = 0
                user.locked_until = None

                db.session.commit()


        # -------------------------------------------
        # Successful Login
        # -------------------------------------------

        if user and bcrypt.check_password_hash(
            user.password_hash,
            password
        ):

            user.failed_attempts = 0
            user.locked_until = None

            db.session.commit()

            login_user(user)

            session.permanent = True

            log_security_event(
                "LOGIN_SUCCESS",
                username
            )

            flash(
                "Login successful.",
                "success"
            )

            return redirect(
                url_for("dashboard")
            )


        # -------------------------------------------
        # Failed Login
        # -------------------------------------------

        log_security_event(
            "LOGIN_FAILED",
            username
        )

        if user:

            user.failed_attempts += 1

            if user.failed_attempts >= MAX_FAILED_ATTEMPTS:

                user.locked_until = (
                    int(time.time())
                    + LOCKOUT_SECONDS
                )

                log_security_event(
                    "ACCOUNT_LOCKED",
                    username
                )

                db.session.commit()

                flash(
                    "Too many failed login attempts. "
                    "Your account has been locked for 5 minutes.",
                    "error"
                )

                return render_template(
                    "login.html"
                )

            db.session.commit()

            attempts_remaining = (
                MAX_FAILED_ATTEMPTS
                - user.failed_attempts
            )

            flash(
                f"Invalid username or password. "
                f"{attempts_remaining} attempts remaining.",
                "error"
            )

        else:

            flash(
                "Invalid username or password.",
                "error"
            )


    return render_template(
        "login.html"
    )


        # -------------------------------------------
        # Check Account Lock
        # -------------------------------------------

    if user and user.locked_until:

        current_time = int(time.time())

        if current_time < user.locked_until:

            remaining_seconds = (
                user.locked_until
                - current_time
            )

            flash(
                f"Account temporarily locked. "
                f"Try again in {remaining_seconds} seconds.",
                "error"
            )

            log_security_event(
                "LOCKED_LOGIN_ATTEMPT",
                username
            )

            return render_template(
                "login.html"
            )

        else:

            user.failed_attempts = 0
            user.locked_until = None

            db.session.commit()


        # -------------------------------------------
        # Successful Login
        # -------------------------------------------

    if user and bcrypt.check_password_hash(
        user.password_hash,
        password
    ):

        user.failed_attempts = 0
        user.locked_until = None

        db.session.commit()

        login_user(user)

        session.permanent = True

        log_security_event(
            "LOGIN_SUCCESS",
            username
        )

        flash(
            "Login successful.",
            "success"
        )

        return redirect(
            url_for("dashboard")
        )


        # -------------------------------------------
        # Failed Login
        # -------------------------------------------

        log_security_event(
            "LOGIN_FAILED",
            username
        )


        if user:

            user.failed_attempts += 1


            if user.failed_attempts >= MAX_FAILED_ATTEMPTS:

                user.locked_until = (
                    int(time.time())
                    + LOCKOUT_SECONDS
                )

                log_security_event(
                    "ACCOUNT_LOCKED",
                    username
                )

                db.session.commit()

                flash(
                    "Too many failed login attempts. "
                    "Your account has been locked for 5 minutes.",
                    "error"
                )

                return render_template(
                    "login.html"
                )


            db.session.commit()


            attempts_remaining = (
                MAX_FAILED_ATTEMPTS
                - user.failed_attempts
            )

            flash(
                f"Invalid username or password. "
                f"{attempts_remaining} attempts remaining.",
                "error"
            )

        else:

            flash(
                "Invalid username or password.",
                "error"
            )


    return render_template(
        "login.html"
    )


# ---------------------------------------------------
# Protected Dashboard
# ---------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():

    return render_template(
        "dashboard.html",
        user=current_user
    )

@app.route("/admin")
@login_required
@admin_required
def admin():

    log_security_event(
        "ADMIN_ACCESS",
        current_user.username
    )

    stats, recent_events = (
        get_security_dashboard_data()
    )

    return render_template(
        "admin.html",
        user=current_user,
        stats=stats,
        recent_events=recent_events
    )

@app.errorhandler(403)
def forbidden(error):

    return render_template(
        "403.html"
    ), 403
# ---------------------------------------------------
# Logout
# ---------------------------------------------------

@app.route("/logout")
@login_required
def logout():

    username = current_user.username

    log_security_event(
        "LOGOUT",
        username
    )

    logout_user()

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(
        url_for("home")
    )


# ---------------------------------------------------
# Run Application
# ---------------------------------------------------

if __name__ == "__main__":

    with app.app_context():
        db.create_all()

    app.run(
        debug=True,
        port=5050
    )