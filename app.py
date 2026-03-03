from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import joblib
import requests
import os
from urllib.parse import urlparse
from werkzeug.security import generate_password_hash, check_password_hash

# ==============================
# APP CONFIG
# ==============================
app = Flask(__name__)
app.secret_key = "supersecretkey"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "users.db")

# ==============================
# LOAD ML MODEL
# ==============================
model = joblib.load("email_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

# ==============================
# GOOGLE SAFE BROWSING API
# ==============================
API_KEY = "AIzaSyDKjBQo7y_AoxeuWwn2pSeL-UHauDl7OFA"

# ==============================
# DATABASE
# ==============================
def get_db():
    return sqlite3.connect(DB_PATH)

def create_tables():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            password TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS email_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            result TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS website_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            result TEXT
        )
    """)

    conn.commit()
    conn.close()

create_tables()

# ==============================
# HOME
# ==============================
@app.route("/")
def home():
    return render_template("home.html")

# ==============================
# REGISTER
# ==============================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        password = generate_password_hash(request.form["password"])

        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute("INSERT INTO users (email, password) VALUES (?,?)", (email, password))
            conn.commit()
            conn.close()
            return redirect(url_for("login"))
        except:
            return "User already exists"

    return render_template("register.html")

# ==============================
# LOGIN
# ==============================
from werkzeug.security import check_password_hash
from flask import render_template, request, redirect, url_for, session

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        email = request.form.get("email").strip()
        password = request.form.get("password").strip()

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email=?", (email,))
        user = cur.fetchone()
        conn.close()

        if user is None:
            error = "User not registered. Please register first."
        elif not check_password_hash(user[2], password):
            error = "Invalid password."
        else:
            session["user"] = email
            return redirect(url_for("dashboard"))

    return render_template("login.html", error=error)

# ==============================
# DASHBOARD
# ==============================
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=session["user"])

# ==============================
# EMAIL SPAM CHECK
# ==============================
@app.route("/email-check", methods=["GET", "POST"])
def email_check():
    if "user" not in session:
        return redirect(url_for("login"))

    result = None
    score_text = None
    risk_label = None
    explanation = []

    if request.method == "POST":
        text = request.form["email_text"]
        vec = vectorizer.transform([text])
        prediction = model.predict(vec)[0]

        if prediction == 1:
            result = "⚠️ Spam / Phishing Email Detected"
            score_text = "Spam Risk Score: 80%"
            risk_label = "High Risk"
            explanation = [
                "Email uses promotional or urgent language",
                "Encourages quick user action",
                "Matches known spam or phishing patterns"
            ]
            log_result = "spam"
        else:
            result = "✅ Legitimate Email"
            score_text = "Safe Confidence Score: 45%"
            risk_label = "Low Risk"
            explanation = [
                "Language is neutral and informational",
                "No suspicious offers or threats detected",
                "Does not request sensitive information"
            ]
            log_result = "legit"

        conn = get_db()
        cur = conn.cursor()
        cur.execute("INSERT INTO email_logs (result) VALUES (?)", (log_result,))
        conn.commit()
        conn.close()

    return render_template(
        "email_check.html",
        result=result,
        score_text=score_text,
        risk_label=risk_label,
        explanation=explanation
    )

# ==============================
# WEBSITE TRUST CHECK
# ==============================
@app.route("/website-check", methods=["GET", "POST"])
def website_check():
    if "user" not in session:
        return redirect(url_for("login"))

    result = None
    risk_level = None
    explanation = []
    https_status = None
    domain = None

    if request.method == "POST":
        url = request.form["url"]

        if not url.startswith("http"):
            url = "http://" + url

        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        # HTTPS CHECK
        if parsed.scheme == "https":
            https_status = "HTTPS Enabled"
            explanation.append("Website uses HTTPS encryption")
        else:
            https_status = "HTTP Only"
            explanation.append("Website does not use HTTPS")

        # DOMAIN ANALYSIS
        domain_risk = 0

        if len(domain) > 20:
            domain_risk += 1
            explanation.append("Long domain names are often suspicious")

        if "-" in domain:
            domain_risk += 1
            explanation.append("Hyphenated domains may imitate trusted brands")

        for ch in domain:
            if ch.isdigit():
                domain_risk += 1
                explanation.append("Numbers in domain may indicate auto-generated domain")
                break

        if domain.count(".") > 2:
            domain_risk += 1
            explanation.append("Multiple subdomains can hide malicious pages")

        # GOVERNMENT DOMAIN ADJUSTMENT
        if domain.endswith(".gov.in"):
            domain_risk = max(domain_risk - 1, 0)
            explanation.append("Government domain detected (.gov.in)")

        # GOOGLE SAFE BROWSING
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

        payload = {
            "client": {"clientId": "cyber-project", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        response = requests.post(api_url, json=payload)
        data = response.json()

        if "matches" in data:
            result = "⚠️ Unsafe Website Detected"
            risk_level = "High"
            explanation.append("Listed in Google Safe Browsing database")
            log_result = "unsafe"
        elif domain_risk >= 3:
            result = "⚠️ High Risk Website"
            risk_level = "High"
            log_result = "unsafe"
        elif domain_risk == 2:
            result = "⚠️ Medium Risk Website"
            risk_level = "Medium"
            log_result = "unsafe"
        else:
            result = "✅ Website Appears Safe"
            risk_level = "Low"
            log_result = "safe"

        conn = get_db()
        cur = conn.cursor()
        cur.execute("INSERT INTO website_logs (result) VALUES (?)", (log_result,))
        conn.commit()
        conn.close()
        

    return render_template(
        "website_check.html",
        result=result,
        risk_level=risk_level,
        explanation=explanation,
        https_status=https_status,
        domain=domain
    )

# ==============================
# ANALYTICS
# ==============================
@app.route("/analytics")
def analytics():
    if "user" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    cursor = conn.cursor()

    # ===============================
    # BASIC COUNTS
    # ===============================
    cursor.execute("SELECT COUNT(*) FROM email_logs")
    total_emails = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM email_logs WHERE result='spam'")
    spam_emails = cursor.fetchone()[0]

    legit_emails = total_emails - spam_emails

    cursor.execute("SELECT COUNT(*) FROM website_logs")
    total_websites = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM website_logs WHERE result='unsafe'")
    unsafe_websites = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM website_logs WHERE result='safe'")
    safe_websites = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM website_logs WHERE result='medium'")
    medium_websites = cursor.fetchone()[0]

    # ===============================
    # LINE CHART DATA (TREND)
    # ===============================
    cursor.execute("""
        SELECT DATE(created_at), COUNT(*)
        FROM email_logs
        WHERE result='spam'
        GROUP BY DATE(created_at)
        ORDER BY DATE(created_at)
    """)
    email_trend = cursor.fetchall()

    cursor.execute("""
        SELECT DATE(created_at), COUNT(*)
        FROM website_logs
        WHERE result='unsafe'
        GROUP BY DATE(created_at)
        ORDER BY DATE(created_at)
    """)
    website_trend = cursor.fetchall()

    conn.close()

    # Prepare chart data
    dates = [row[0] for row in email_trend]
    spam_counts = [row[1] for row in email_trend]
    unsafe_counts = [row[1] for row in website_trend]

    return render_template(
        "analytics.html",
        total_emails=total_emails,
        spam_emails=spam_emails,
        legit_emails=legit_emails,
        total_websites=total_websites,
        safe_websites=safe_websites,
        medium_websites=medium_websites,
        unsafe_websites=unsafe_websites,
        dates=dates,
        spam_counts=spam_counts,
        unsafe_counts=unsafe_counts
    )


# ==============================
# LOGOUT
# ==============================
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

# ==============================
# RUN
# ==============================
if __name__ == "__main__":
    app.run(debug=True)
