"""
Köhnə PythonAnywhere saytının Render + Supabase versiyası.

Köhnə saytın kodu (kohne_sayt.py) OLDUĞU KİMİ qalır: dizayn, səhifələr, funksiyalar.
Bu fayl yalnız verilənlər bazasını SQLite-dən Supabase Postgres-ə çevirir,
yeni davamiyyət saytından loginsiz keçid (/sso) və köhnə məlumatı köçürmə (/kocur) əlavə edir.
"""
import csv
import hashlib
import io
import json
import os
import re
import secrets
import sqlite3 as _sqlite
import tempfile
import urllib.request
from datetime import date, timedelta
from functools import wraps

import psycopg2
import psycopg2.extras
from flask import (Flask, Response, abort, flash, g, redirect,
                   render_template_string, request, session, url_for)
from jinja2 import DictLoader
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL təyin olunmayıb (Render → Environment).")
SUPABASE_URL = os.environ.get("SUPABASE_URL", "https://wfagjimyjvuazvofulke.supabase.co")
SUPABASE_KEY = os.environ.get("SUPABASE_ANON_KEY", "sb_publishable_GDCQZViZ1kLgYeRecYwQcA_f8PceevS")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or hashlib.sha256(("portal|" + DATABASE_URL).encode()).hexdigest()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=bool(os.environ.get("RENDER")))

NOVLER = ["Üzrsüz", "Üzrlü (xəstəlik)", "Üzrlü (digər)"]
NOVSHORT = {"Üzrsüz": "Üzrsüz", "Üzrlü (xəstəlik)": "Xəstəlik", "Üzrlü (digər)": "Üzrlü"}


class sqlite3:  # köhnə kodda "sqlite3.IntegrityError" işləməyə davam etsin
    IntegrityError = psycopg2.IntegrityError


# ---------------------------------------------------------------- verilənlər bazası (Postgres)
_TR = str.maketrans({"Ə": "e", "ə": "e", "İ": "i", "I": "i", "ı": "i", "Ö": "o", "ö": "o",
                     "Ü": "u", "ü": "u", "Ç": "c", "ç": "c", "Ş": "s", "ş": "s", "Ğ": "g", "ğ": "g"})


def norm(x):
    return (x or "").translate(_TR).lower()


class Cur:
    def __init__(self, cur, lastrowid=None):
        self.c, self.lastrowid = cur, lastrowid

    def fetchone(self):
        return self.c.fetchone()

    def fetchall(self):
        return self.c.fetchall()

    def __iter__(self):
        return iter(self.c)


class DB:
    """sqlite3-ə bənzər sadə qabıq: '?' işarələri, r['ad'] və r[0] ilə oxuma, lastrowid."""

    def __init__(self):
        self.conn = psycopg2.connect(DATABASE_URL)
        c = self.conn.cursor()
        c.execute("SET search_path TO portal")
        self.conn.commit()

    def execute(self, sql, params=()):
        cur = self.conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        sql = sql.replace("?", "%s")
        ret = sql.lstrip().upper().startswith("INSERT INTO STUDENTS")
        if ret:
            sql += " RETURNING id"
        try:
            cur.execute(sql, list(params))
        except Exception:
            self.conn.rollback()
            raise
        return Cur(cur, cur.fetchone()[0] if ret else None)

    def commit(self):
        self.conn.commit()

    def close(self):
        try:
            self.conn.rollback()
        finally:
            self.conn.close()


def db():
    if "db" not in g:
        g.db = DB()
    return g.db


@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()


def init_db():
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE SCHEMA IF NOT EXISTS portal;
        SET search_path TO portal;
        CREATE TABLE IF NOT EXISTS users(
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            pw TEXT NOT NULL,
            role TEXT NOT NULL,
            mekteb TEXT,
            ad TEXT
        );
        CREATE TABLE IF NOT EXISTS students(
            id SERIAL PRIMARY KEY,
            soyad TEXT NOT NULL,
            ad TEXT NOT NULL,
            ata_adi TEXT NOT NULL,
            mekteb TEXT NOT NULL,
            utis TEXT NOT NULL,
            fin TEXT NOT NULL UNIQUE,
            sinif TEXT NOT NULL,
            yaradilib TIMESTAMP DEFAULT now()
        );
        CREATE TABLE IF NOT EXISTS absences(
            id SERIAL PRIMARY KEY,
            student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
            tarix TEXT NOT NULL,
            nov TEXT NOT NULL,
            qeyd TEXT,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            yaradilib TIMESTAMP DEFAULT now()
        );
        CREATE TABLE IF NOT EXISTS restorations(
            id SERIAL PRIMARY KEY,
            student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
            tarix TEXT NOT NULL,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            yaradilib TIMESTAMP DEFAULT now()
        );
        DROP VIEW IF EXISTS events;
        CREATE VIEW events AS
            SELECT id, student_id, tarix, nov, qeyd, user_id, 'y'::text AS tip FROM absences
            UNION ALL
            SELECT id, student_id, tarix, 'Bərpa olundu'::text, ''::text, user_id, 'b'::text FROM restorations;
        CREATE INDEX IF NOT EXISTS ix_abs_tarix ON absences(tarix);
        CREATE INDEX IF NOT EXISTS ix_stu_mekteb ON students(mekteb, sinif);
        CREATE INDEX IF NOT EXISTS ix_abs_student ON absences(student_id);
        ALTER TABLE users ENABLE ROW LEVEL SECURITY;
        ALTER TABLE students ENABLE ROW LEVEL SECURITY;
        ALTER TABLE absences ENABLE ROW LEVEL SECURITY;
        ALTER TABLE restorations ENABLE ROW LEVEL SECURITY;
        """
    )
    cur.execute("SELECT 1 FROM portal.users WHERE role='admin'")
    if not cur.fetchone():
        pw = os.environ.get("ADMIN_PASSWORD", "admin12345")
        cur.execute("INSERT INTO portal.users(username,pw,role,ad) VALUES('admin',%s,'admin','Administrator')",
                    (generate_password_hash(pw),))
    conn.commit()
    conn.close()


init_db()


# ---------------------------------------------------------------- yeni saytdan loginsiz keçid
@app.before_request
def sso_gate():
    """Yeni davamiyyət saytı Supabase girişini (token) bura POST edir, burada təsdiqlənir."""
    if request.path != "/sso":
        return None
    token = request.form.get("token", "") if request.method == "POST" else ""
    if not token:
        return redirect("/login")
    try:
        req = urllib.request.Request(SUPABASE_URL + "/auth/v1/user",
                                     headers={"Authorization": "Bearer " + token, "apikey": SUPABASE_KEY})
        with urllib.request.urlopen(req, timeout=10) as r:
            info = json.load(r)
        uid = info["id"]
    except Exception:
        flash("Giriş təsdiqlənmədi. Yeni saytdan yenidən daxil olub təkrar cəhd edin.", "err")
        return redirect("/login")
    d = db()
    p = d.execute("SELECT role, school_name FROM public.profiles WHERE user_id=?", (uid,)).fetchone()
    if not p:
        flash("Profil tapılmadı. İdarəyə müraciət edin.", "err")
        return redirect("/login")
    if p["role"] == "admin":
        u = d.execute("SELECT * FROM users WHERE role='admin' ORDER BY id LIMIT 1").fetchone()
    else:
        email = (info.get("email") or uid).lower()
        u = d.execute("SELECT * FROM users WHERE username=?", (email,)).fetchone()
        if not u:
            d.execute("INSERT INTO users(username,pw,role,mekteb,ad) VALUES(?,?,?,?,?)",
                      (email, generate_password_hash(secrets.token_hex(16)), "muellim",
                       p["school_name"], p["school_name"]))
            d.commit()
            u = d.execute("SELECT * FROM users WHERE username=?", (email,)).fetchone()
        elif u["mekteb"] != p["school_name"]:
            d.execute("UPDATE users SET mekteb=?, ad=? WHERE id=?", (p["school_name"], p["school_name"], u["id"]))
            d.commit()
            u = d.execute("SELECT * FROM users WHERE id=?", (u["id"],)).fetchone()
    session.clear()
    session["uid"] = u["id"]
    session["csrf"] = secrets.token_hex(16)
    return redirect("/")


# ---------------------------------------------------------------- köhnə davamiyyet.db faylının köçürülməsi
KOCUR = """{% extends 'base.html' %}{% block body %}
<h1>Köhnə məlumatın köçürülməsi</h1>
<form method="post" enctype="multipart/form-data" class="card" style="max-width:520px">
<input type="hidden" name="csrf" value="{{ csrf }}">
<p class="mut">PythonAnywhere-dən endirdiyiniz davamiyyet.db faylını seçin. Bir dəfə edilir.</p>
<input type="file" name="db" required>
<p><button>Köçürməyə başla</button></p>
{% if msg %}<p><b>{{ msg }}</b></p>{% endif %}</form>{% endblock %}"""


def import_old(path):
    src = _sqlite.connect(path)
    conn = db().conn
    cur = conn.cursor()
    ex = psycopg2.extras.execute_values
    users = src.execute("SELECT id,username,pw,role,mekteb,ad FROM users WHERE role!='admin'").fetchall()
    stu = src.execute("SELECT id,soyad,ad,ata_adi,mekteb,utis,fin,sinif FROM students").fetchall()
    if users:
        ex(cur, "INSERT INTO users(id,username,pw,role,mekteb,ad) VALUES %s ON CONFLICT DO NOTHING", users)
    if stu:
        ex(cur, "INSERT INTO students(id,soyad,ad,ata_adi,mekteb,utis,fin,sinif) VALUES %s ON CONFLICT DO NOTHING", stu)
    cur.execute("SELECT id FROM users")
    uids = {r[0] for r in cur.fetchall()}
    cur.execute("SELECT id FROM students")
    sids = {r[0] for r in cur.fetchall()}
    ab = [(r[0], r[1], r[2], r[3], r[4], r[5] if r[5] in uids else None)
          for r in src.execute("SELECT id,student_id,tarix,nov,qeyd,user_id FROM absences") if r[1] in sids]
    rs = [(r[0], r[1], r[2], r[3] if r[3] in uids else None)
          for r in src.execute("SELECT id,student_id,tarix,user_id FROM restorations") if r[1] in sids]
    if ab:
        ex(cur, "INSERT INTO absences(id,student_id,tarix,nov,qeyd,user_id) VALUES %s ON CONFLICT DO NOTHING", ab)
    if rs:
        ex(cur, "INSERT INTO restorations(id,student_id,tarix,user_id) VALUES %s ON CONFLICT DO NOTHING", rs)
    for t in ("users", "students", "absences", "restorations"):
        cur.execute(f"SELECT setval(pg_get_serial_sequence('{t}','id'), (SELECT COALESCE(MAX(id),1) FROM {t}))")
    conn.commit()
    src.close()
    return len(users), len(stu), len(ab), len(rs)


@app.route("/kocur", methods=["GET", "POST"])
def migrate():
    u = current_user()
    if not u or u["role"] != "admin":
        abort(403)
    g.user = u
    msg = ""
    if request.method == "POST":
        f = request.files.get("db")
        if f:
            fd, path = tempfile.mkstemp(suffix=".db")
            os.close(fd)
            try:
                f.save(path)
                a, b, c, d = import_old(path)
                msg = f"Bitdi: {a} direktor hesabı, {b} şagird, {c} yayınma, {d} bərpa qeydi köçürüldü."
            except Exception as e:
                db().conn.rollback()
                msg = "Xəta: " + str(e)
            finally:
                os.remove(path)
    return render_template_string(KOCUR, msg=msg)


# ---------------------------------------------------------------- köhnə saytın qalan hissəsi (dəyişdirilmədən)
_p = os.path.join(BASE, "kohne_sayt.py")
with open(_p, encoding="utf-8") as _f:
    _src = _f.read()
_i = _src.index("giriş və təhlükəsizlik")
_src = _src[_src.rfind("\n", 0, _i) + 1:]
exec(compile(_src, _p, "exec"), globals())
