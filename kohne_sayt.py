import csv
import io
import os
import re
import secrets
import sqlite3
from datetime import date, timedelta
from functools import wraps

from flask import (Flask, Response, abort, flash, g, redirect,
                   render_template_string, request, session, url_for)
from jinja2 import DictLoader
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE, "davamiyyet.db")
KEY_PATH = os.path.join(BASE, "secret.key")

app = Flask(__name__)
if not os.path.exists(KEY_PATH):
    with open(KEY_PATH, "w") as f:
        f.write(secrets.token_hex(32))
with open(KEY_PATH) as f:
    app.secret_key = f.read().strip()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

NOVLER = ["Üzrsüz", "Üzrlü (xəstəlik)", "Üzrlü (digər)"]
NOVSHORT = {"Üzrsüz": "Üzrsüz", "Üzrlü (xəstəlik)": "Xəstəlik", "Üzrlü (digər)": "Üzrlü"}


# ---------------------------------------------------------------- verilənlər bazası
_TR = str.maketrans({"Ə": "e", "ə": "e", "İ": "i", "I": "i", "ı": "i", "Ö": "o", "ö": "o",
                     "Ü": "u", "ü": "u", "Ç": "c", "ç": "c", "Ş": "s", "ş": "s", "Ğ": "g", "ğ": "g"})


def norm(x):
    return (x or "").translate(_TR).lower()


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.create_function("norm", 1, norm)
    return g.db


@app.teardown_appcontext
def close_db(_):
    conn = g.pop("db", None)
    if conn:
        conn.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            pw TEXT NOT NULL,
            role TEXT NOT NULL,
            mekteb TEXT,
            ad TEXT
        );
        CREATE TABLE IF NOT EXISTS students(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            soyad TEXT NOT NULL,
            ad TEXT NOT NULL,
            ata_adi TEXT NOT NULL,
            mekteb TEXT NOT NULL,
            utis TEXT NOT NULL,
            fin TEXT NOT NULL UNIQUE,
            sinif TEXT NOT NULL,
            yaradilib TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS absences(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
            tarix TEXT NOT NULL,
            nov TEXT NOT NULL,
            qeyd TEXT,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            yaradilib TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS restorations(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
            tarix TEXT NOT NULL,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            yaradilib TEXT DEFAULT CURRENT_TIMESTAMP
        );
        DROP VIEW IF EXISTS events;
        CREATE VIEW events AS
            SELECT id, student_id, tarix, nov, qeyd, user_id, 'y' AS tip FROM absences
            UNION ALL
            SELECT id, student_id, tarix, 'Bərpa olundu', '', user_id, 'b' FROM restorations;
        CREATE INDEX IF NOT EXISTS ix_abs_tarix ON absences(tarix);
        CREATE INDEX IF NOT EXISTS ix_stu_mekteb ON students(mekteb, sinif);
        """
    )
    if not conn.execute("SELECT 1 FROM users WHERE role='admin'").fetchone():
        pw = os.environ.get("ADMIN_PASSWORD", "admin12345")
        conn.execute(
            "INSERT INTO users(username,pw,role,ad) VALUES('admin',?, 'admin','Administrator')",
            (generate_password_hash(pw),),
        )
    conn.commit()
    conn.close()


init_db()


# ---------------------------------------------------------------- giriş və təhlükəsizlik
def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    return db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()


def login_required(admin=False):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            u = current_user()
            if not u:
                return redirect(url_for("login"))
            if admin and u["role"] != "admin":
                abort(403)
            g.user = u
            return fn(*a, **kw)
        return wrapper
    return deco


@app.before_request
def csrf_protect():
    if request.method == "POST":
        if not session.get("csrf") or request.form.get("csrf") != session["csrf"]:
            abort(400, "Sessiya etibarsızdır. Səhifəni yeniləyib təkrar cəhd edin.")


@app.context_processor
def inject():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return dict(csrf=session["csrf"], user=getattr(g, "user", None), NOVLER=NOVLER, NOVSHORT=NOVSHORT,
                today=date.today().isoformat())


def mask_fin(f):
    return f[:2] + "•••" + f[-2:]


app.jinja_env.filters["mask_fin"] = mask_fin
app.jinja_env.filters["azd"] = lambda t: f"{t[8:10]}.{t[5:7]}.{t[0:4]}" if t else ""


def school_scope(alias=""):
    """Direktor yalnız öz məktəbini görür, admin hamısını."""
    p = alias + "." if alias else ""
    if g.user["role"] == "admin":
        return "1=1", []
    return f"{p}mekteb=?", [g.user["mekteb"]]


def clean(s):
    return re.sub(r"\s+", " ", (s or "").strip())


# ---------------------------------------------------------------- giriş / çıxış
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = db().execute("SELECT * FROM users WHERE username=?",
                         (clean(request.form.get("username")).lower(),)).fetchone()
        if u and check_password_hash(u["pw"], request.form.get("password", "")):
            session.clear()
            session["uid"] = u["id"]
            session["csrf"] = secrets.token_hex(16)
            return redirect(url_for("index"))
        flash("İstifadəçi adı və ya şifrə yanlışdır.", "err")
    return render_template_string(T["login.html"])


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/sifre", methods=["GET", "POST"])
@login_required()
def change_password():
    if request.method == "POST":
        if not check_password_hash(g.user["pw"], request.form.get("old", "")):
            flash("Köhnə şifrə yanlışdır.", "err")
        elif len(request.form.get("new", "")) < 8:
            flash("Yeni şifrə ən azı 8 simvol olmalıdır.", "err")
        else:
            db().execute("UPDATE users SET pw=? WHERE id=?",
                         (generate_password_hash(request.form["new"]), g.user["id"]))
            db().commit()
            flash("Şifrə dəyişdirildi.", "ok")
            return redirect(url_for("index"))
    return render_template_string(T["password.html"])


# ---------------------------------------------------------------- əsas səhifə
@app.route("/qeyd-et")
@login_required()
def qeyd_form():
    return qeyd_page()


@app.route("/")
@login_required()
def index():
    d = db()
    admin = g.user["role"] == "admin"
    w, p = school_scope("x")
    bugun = date.today().isoformat()
    ay = bugun[:8] + "01"
    data = {}
    for r in d.execute(f"""SELECT x.mekteb AS m, COUNT(DISTINCT x.id) AS sagird,
            COUNT(CASE WHEN a.tarix=? THEN 1 END) AS bugun,
            COUNT(CASE WHEN a.tarix>=? THEN 1 END) AS ay, COUNT(a.id) AS cemi
            FROM students x LEFT JOIN absences a ON a.student_id=x.id WHERE {w} GROUP BY x.mekteb""",
                       [bugun, ay] + p):
        data[r["m"]] = dict(m=r["m"], sagird=r["sagird"], bugun=r["bugun"], ay=r["ay"], cemi=r["cemi"], muellim=0)
    uq, up = "SELECT mekteb, COUNT(*) c FROM users WHERE role='muellim'", []
    if not admin:
        uq += " AND mekteb=?"; up.append(g.user["mekteb"])
    for r in d.execute(uq + " GROUP BY mekteb", up):
        data.setdefault(r["mekteb"], dict(m=r["mekteb"], sagird=0, bugun=0, ay=0, cemi=0, muellim=0))["muellim"] = r["c"]
    rows = sorted(data.values(), key=lambda x: x["m"] or "")
    tot = {k: sum(x[k] for x in rows) for k in ("sagird", "bugun", "ay", "cemi")}
    w2, p2 = school_scope("s")
    recent = d.execute(f"""SELECT a.*, s.soyad, s.ad, s.sinif, s.mekteb, u.ad AS qeyd_eden FROM events a
            JOIN students s ON s.id=a.student_id LEFT JOIN users u ON u.id=a.user_id
            WHERE {w2} ORDER BY a.tarix DESC, a.id DESC LIMIT 8""", p2).fetchall()
    return render_template_string(T["dash.html"], rows=rows, tot=tot, mektebler=[x["m"] for x in rows],
                                  recent=recent, side=side_stats())


def side_stats():
    w, p = school_scope("s")
    d = db()
    today = date.today()
    start = today - timedelta(days=13)
    ay = today.replace(day=1).isoformat()
    cnt = {r[0]: r[1] for r in d.execute(
        f"SELECT a.tarix, COUNT(*) FROM absences a JOIN students s ON s.id=a.student_id "
        f"WHERE {w} AND a.tarix>=? GROUP BY a.tarix", p + [start.isoformat()])}
    mx = max(cnt.values(), default=0) or 1
    days = []
    for i in range(14):
        x = start + timedelta(days=i)
        n = cnt.get(x.isoformat(), 0)
        days.append(dict(l=x.strftime("%d.%m"), full=x.strftime("%d.%m.%Y"), n=n, h=round(n / mx * 100)))
    top = d.execute(
        f"""SELECT s.id, s.soyad, s.ad, s.sinif, s.mekteb, COUNT(a.id) AS c FROM absences a
            JOIN students s ON s.id=a.student_id WHERE {w} AND a.tarix>=?
            GROUP BY s.id ORDER BY c DESC, s.soyad LIMIT 5""", p + [ay]).fetchall()
    month = d.execute(
        f"SELECT COUNT(*) FROM absences a JOIN students s ON s.id=a.student_id WHERE {w} AND a.tarix>=?",
        p + [ay]).fetchone()[0]
    return dict(days=days, top=top, bugun=cnt.get(today.isoformat(), 0), ay=month)


def qeyd_page(f=None, new=False):
    w, p = school_scope("s")
    rows = db().execute(
        f"""SELECT a.*, s.soyad, s.ad, s.ata_adi, s.sinif, s.mekteb FROM events a
            JOIN students s ON s.id=a.student_id WHERE a.tarix=? AND {w} ORDER BY a.id DESC""",
        [date.today().isoformat()] + p).fetchall()
    return render_template_string(T["qeyd.html"], rows=rows, f=f or {}, new=new)


@app.route("/qeyd", methods=["POST"])
@login_required()
def qeyd():
    d = db()
    tarix = request.form.get("tarix", "")
    nov = request.form.get("nov", "")
    try:
        date.fromisoformat(tarix)
    except ValueError:
        flash("Tarix düzgün deyil.", "err")
        return qeyd_page()
    berpa = request.form.get("act") == "berpa"
    if nov not in NOVLER and not berpa:
        abort(400)
    sid = request.form.get("sid", "")
    if sid.isdigit():
        s = get_student(int(sid))
    else:
        if berpa:
            flash("Bərpa üçün şagirdi siyahıdan seçin.", "err")
            return qeyd_page()
        f = {k: clean(request.form.get(k)) for k in ("soyad", "ad", "ata_adi", "sinif", "utis", "fin", "mekteb")}
        if g.user["role"] != "admin":
            f["mekteb"] = g.user["mekteb"]
        f["fin"] = f["fin"].upper()
        err = None
        if not all(f.values()):
            err = "Şagirdi siyahıdan seçin və ya yeni şagirdin bütün məlumatlarını yazın."
        elif not re.fullmatch(r"[A-Z0-9]{7}", f["fin"]):
            err = "FİN kod 7 simvoldan (hərf və rəqəm) ibarət olmalıdır."
        elif not f["utis"].isdigit():
            err = "UTİS kod yalnız rəqəmlərdən ibarət olmalıdır."
        if err:
            flash(err, "err")
            return qeyd_page(f, True)
        s = d.execute("SELECT * FROM students WHERE fin=?", (f["fin"],)).fetchone()
        if s and g.user["role"] != "admin" and s["mekteb"] != g.user["mekteb"]:
            flash("Bu FİN kodlu şagird başqa məktəbdə qeydiyyatdadır.", "err")
            return qeyd_page(f, True)
        if not s:
            cur = d.execute(
                "INSERT INTO students(soyad,ad,ata_adi,mekteb,utis,fin,sinif) VALUES(?,?,?,?,?,?,?)",
                (f["soyad"], f["ad"], f["ata_adi"], f["mekteb"], f["utis"], f["fin"], f["sinif"]))
            s = d.execute("SELECT * FROM students WHERE id=?", (cur.lastrowid,)).fetchone()
    if berpa:
        d.execute("DELETE FROM restorations WHERE student_id=? AND tarix=?", (s["id"], tarix))
        d.execute("INSERT INTO restorations(student_id,tarix,user_id) VALUES(?,?,?)",
                  (s["id"], tarix, g.user["id"]))
        d.commit()
        flash(f"Bərpa olundu: {s['soyad']} {s['ad']} ({s['sinif']}), {tarix[8:10]}.{tarix[5:7]}.{tarix[:4]}", "ok")
        return redirect(url_for("qeyd_form"))
    d.execute("DELETE FROM absences WHERE student_id=? AND tarix=?", (s["id"], tarix))
    d.execute("INSERT INTO absences(student_id,tarix,nov,qeyd,user_id) VALUES(?,?,?,?,?)",
              (s["id"], tarix, nov, clean(request.form.get("qeyd"))[:200], g.user["id"]))
    d.commit()
    flash(f"Qeyd edildi: {s['soyad']} {s['ad']} ({s['sinif']}), {tarix[8:10]}.{tarix[5:7]}.{tarix[:4]}", "ok")
    return redirect(url_for("qeyd_form"))


@app.route("/api/axtar")
@login_required()
def api_search():
    q = clean(request.args.get("q"))
    if len(q) < 2:
        return {"r": []}
    w, p = school_scope()
    sql = f"SELECT id,soyad,ad,ata_adi,sinif,mekteb FROM students WHERE {w}"
    for part in q.split():
        sql += " AND norm(soyad||' '||ad||' '||ata_adi||' '||utis) LIKE ?"
        p.append(f"%{norm(part)}%")
    sql += " ORDER BY soyad, ad LIMIT 8"
    return {"r": [dict(id=r["id"], ad=f"{r['soyad']} {r['ad']} {r['ata_adi']}", sinif=r["sinif"],
                       mekteb=r["mekteb"] if g.user["role"] == "admin" else "")
                  for r in db().execute(sql, p)]}


@app.route("/mekteb")
@login_required()
def school():
    ad = clean(request.args.get("ad"))
    if g.user["role"] != "admin":
        ad = g.user["mekteb"]
    rows = db().execute(
        """SELECT s.*, COUNT(a.id) AS say, MAX(a.tarix) AS son,
           COALESCE(SUM(CASE WHEN a.nov='Üzrsüz' THEN 1 ELSE 0 END),0) AS uzrsuz
           FROM students s LEFT JOIN absences a ON a.student_id=s.id WHERE s.mekteb=? GROUP BY s.id""", (ad,)).fetchall()
    rows = sorted(rows, key=lambda r: (sinif_key(r["sinif"]), r["soyad"], r["ad"]))
    return render_template_string(T["school.html"], rows=rows, ad=ad)


# ---------------------------------------------------------------- şagirdlər
@app.route("/shagirdler")
@login_required()
def students():
    q = clean(request.args.get("q"))
    sinif = clean(request.args.get("sinif"))
    w, p = school_scope()
    sql = f"SELECT s.*, COUNT(a.id) AS say, MAX(a.tarix) AS son FROM students s LEFT JOIN absences a ON a.student_id=s.id WHERE {w}"
    if q:
        for part in q.split():
            sql += " AND norm(soyad||' '||ad||' '||ata_adi||' '||utis||' '||fin) LIKE ?"
            p.append(f"%{norm(part)}%")
    if sinif:
        sql += " AND sinif=?"
        p.append(sinif)
    sql += " GROUP BY s.id ORDER BY s.mekteb, s.sinif, s.soyad, s.ad LIMIT 300"
    rows = db().execute(sql, p).fetchall()
    return render_template_string(T["students.html"], rows=rows, q=q, sinif=sinif)


@app.route("/shagird/yeni", methods=["GET", "POST"])
@login_required()
def student_new():
    f = {k: clean(request.form.get(k)) for k in
         ("soyad", "ad", "ata_adi", "mekteb", "utis", "fin", "sinif")}
    if request.method == "POST":
        if g.user["role"] != "admin":
            f["mekteb"] = g.user["mekteb"]
        f["fin"] = f["fin"].upper()
        err = None
        if not all(f.values()):
            err = "Bütün xanaları doldurun."
        elif not re.fullmatch(r"[A-Z0-9]{7}", f["fin"]):
            err = "FİN kod 7 simvoldan (hərf və rəqəm) ibarət olmalıdır."
        elif not f["utis"].isdigit():
            err = "UTİS kod yalnız rəqəmlərdən ibarət olmalıdır."
        if err:
            flash(err, "err")
        else:
            try:
                cur = db().execute(
                    "INSERT INTO students(soyad,ad,ata_adi,mekteb,utis,fin,sinif) VALUES(?,?,?,?,?,?,?)",
                    [f[k] for k in ("soyad", "ad", "ata_adi", "mekteb", "utis", "fin", "sinif")])
                db().commit()
                flash("Şagird əlavə edildi.", "ok")
                if request.form.get("next") == "list":
                    return redirect(url_for("students", sinif=f["sinif"]))
                if request.form.get("next") == "absence":
                    return redirect(url_for("absence_new", sid=cur.lastrowid))
                return redirect(url_for("students"))
            except sqlite3.IntegrityError:
                flash("Bu FİN kodlu şagird artıq qeydiyyatdadır.", "err")
    return render_template_string(T["student_new.html"], f=f)


@app.route("/shagird/<int:sid>/sil", methods=["POST"])
@login_required(admin=True)
def student_delete(sid):
    db().execute("DELETE FROM students WHERE id=?", (sid,))
    db().commit()
    flash("Şagird və onun yayınma qeydləri silindi.", "ok")
    return redirect(url_for("students"))


def get_student(sid):
    w, p = school_scope()
    s = db().execute(f"SELECT * FROM students WHERE id=? AND {w}", [sid] + p).fetchone()
    if not s:
        abort(404)
    return s


@app.route("/shagird/<int:sid>")
@login_required()
def student_view(sid):
    s = get_student(sid)
    rows = db().execute(
        "SELECT e.*, u.ad AS qeyd_eden FROM events e LEFT JOIN users u ON u.id=e.user_id "
        "WHERE e.student_id=? ORDER BY e.tarix DESC, e.tip DESC, e.id DESC", (sid,)).fetchall()
    n = sum(1 for r in rows if r["tip"] == "y")
    return render_template_string(T["student.html"], s=s, rows=rows, n=n)


# ---------------------------------------------------------------- buraxılmış dərslər
@app.route("/buraxma/yeni/<int:sid>", methods=["GET", "POST"])
@login_required()
def absence_new(sid):
    s = get_student(sid)
    if request.method == "POST":
        tarix = request.form.get("tarix", "")
        nov = request.form.get("nov", "")
        try:
            date.fromisoformat(tarix)
        except ValueError:
            flash("Tarix düzgün deyil.", "err")
            return render_template_string(T["absence_new.html"], s=s)
        if nov not in NOVLER:
            abort(400)
        db().execute("DELETE FROM absences WHERE student_id=? AND tarix=?", (sid, tarix))
        db().execute(
            "INSERT INTO absences(student_id,tarix,nov,qeyd,user_id) VALUES(?,?,?,?,?)",
            (sid, tarix, nov, clean(request.form.get("qeyd")), g.user["id"]))
        db().commit()
        flash(f"{s['soyad']} {s['ad']} üçün qeyd saxlanıldı.", "ok")
        return redirect(url_for("student_view", sid=sid))
    return render_template_string(T["absence_new.html"], s=s)


@app.route("/buraxma/<int:aid>/sil", methods=["POST"])
@login_required()
def absence_delete(aid):
    w, p = school_scope("s")
    a = db().execute(
        f"SELECT a.id FROM absences a JOIN students s ON s.id=a.student_id WHERE a.id=? AND {w}",
        [aid] + p).fetchone()
    if not a:
        abort(404)
    db().execute("DELETE FROM absences WHERE id=?", (aid,))
    db().commit()
    flash("Qeyd silindi.", "ok")
    return redirect(request.referrer or url_for("index"))


def absence_query():
    w, p = school_scope("s")
    sql = f"""SELECT a.*, s.soyad, s.ad, s.ata_adi, s.mekteb, s.utis, s.fin, s.sinif, u.ad AS qeyd_eden
              FROM events a JOIN students s ON s.id=a.student_id
              LEFT JOIN users u ON u.id=a.user_id WHERE {w}"""
    d1 = request.args.get("d1", "")
    d2 = request.args.get("d2", "")
    sinif = clean(request.args.get("sinif"))
    q = clean(request.args.get("q"))
    mekteb = clean(request.args.get("mekteb"))
    if d1:
        sql += " AND a.tarix>=?"; p.append(d1)
    if d2:
        sql += " AND a.tarix<=?"; p.append(d2)
    if sinif:
        sql += " AND s.sinif=?"; p.append(sinif)
    if mekteb and g.user["role"] == "admin":
        sql += " AND s.mekteb=?"; p.append(mekteb)
    for part in q.split():
        sql += " AND norm(s.soyad||' '||s.ad||' '||s.ata_adi||' '||s.utis) LIKE ?"
        p.append(f"%{norm(part)}%")
    sql += " ORDER BY a.tarix DESC, s.mekteb, s.sinif, s.soyad"
    return sql, p, dict(d1=d1, d2=d2, sinif=sinif, q=q, mekteb=mekteb)


@app.route("/buraxmalar.csv")
@login_required()
def absences_csv():
    sql, p, _ = absence_query()
    out = io.StringIO()
    wr = csv.writer(out, delimiter=";")
    wr.writerow(["Tarix", "Soyadı", "Adı", "Ata adı", "Məktəb", "UTİS kodu", "FİN kodu",
                 "Sinif", "Hadisə", "Görülən tədbir", "Qeyd edən"])
    for r in db().execute(sql, p):
        wr.writerow([r["tarix"], r["soyad"], r["ad"], r["ata_adi"], r["mekteb"], r["utis"],
                     r["fin"], r["sinif"], r["nov"], r["qeyd"], r["qeyd_eden"]])
    return Response("\ufeff" + out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=buraxilan_derslar.csv"})


# ---------------------------------------------------------------- sinif jurnalı
def sinif_key(x):
    m = re.match(r"\d+", x)
    return (int(m.group()) if m else 99, x)


@app.route("/jurnal")
@login_required()
def jurnal():
    admin = g.user["role"] == "admin"
    mekteb = clean(request.args.get("mekteb")) if admin else g.user["mekteb"]
    sinif = clean(request.args.get("sinif"))
    tarix = request.args.get("tarix") or date.today().isoformat()
    try:
        date.fromisoformat(tarix)
    except ValueError:
        tarix = date.today().isoformat()
    d = db()
    mektebler = [r[0] for r in d.execute("SELECT DISTINCT mekteb FROM students ORDER BY 1")] if admin else []
    siniflar, rows = [], []
    if mekteb:
        siniflar = sorted([r[0] for r in d.execute(
            "SELECT DISTINCT sinif FROM students WHERE mekteb=?", (mekteb,))], key=sinif_key)
        if sinif:
            rows = d.execute(
                """SELECT s.*, a.nov, a.qeyd FROM students s
                   LEFT JOIN absences a ON a.id=(SELECT MAX(id) FROM absences WHERE student_id=s.id AND tarix=?)
                   WHERE s.mekteb=? AND s.sinif=? ORDER BY s.soyad, s.ad""", (tarix, mekteb, sinif)).fetchall()
    return render_template_string(T["jurnal.html"], rows=rows, mekteb=mekteb, sinif=sinif,
                                  tarix=tarix, mektebler=mektebler, siniflar=siniflar)


@app.route("/api/buraxma", methods=["POST"])
@login_required()
def api_absence():
    try:
        sid = int(request.form.get("sid", 0))
        tarix = request.form.get("tarix", "")
        date.fromisoformat(tarix)
    except ValueError:
        return {"ok": False}, 400
    get_student(sid)
    nov = request.form.get("nov", "")
    d = db()
    d.execute("DELETE FROM absences WHERE student_id=? AND tarix=?", (sid, tarix))
    if nov in NOVLER:
        d.execute("INSERT INTO absences(student_id,tarix,nov,qeyd,user_id) VALUES(?,?,?,?,?)",
                  (sid, tarix, nov, clean(request.form.get("qeyd"))[:200], g.user["id"]))
    elif nov != "Gəlib":
        return {"ok": False}, 400
    d.commit()
    return {"ok": True}


# ---------------------------------------------------------------- bərpa, redaktə
@app.route("/shagird/<int:sid>/berpa", methods=["POST"])
@login_required()
def restore(sid):
    s = get_student(sid)
    tarix = request.form.get("tarix", "")
    try:
        date.fromisoformat(tarix)
    except ValueError:
        flash("Tarix düzgün deyil.", "err")
        return redirect(url_for("student_view", sid=sid))
    d = db()
    d.execute("DELETE FROM restorations WHERE student_id=? AND tarix=?", (sid, tarix))
    d.execute("INSERT INTO restorations(student_id,tarix,user_id) VALUES(?,?,?)", (sid, tarix, g.user["id"]))
    d.commit()
    flash(f"Bərpa olundu: {s['soyad']} {s['ad']}, {tarix[8:10]}.{tarix[5:7]}.{tarix[:4]}", "ok")
    return redirect(url_for("student_view", sid=sid))


@app.route("/berpa/<int:rid>/sil", methods=["POST"])
@login_required()
def restore_delete(rid):
    w, p = school_scope("s")
    r = db().execute(
        f"SELECT r.id FROM restorations r JOIN students s ON s.id=r.student_id WHERE r.id=? AND {w}",
        [rid] + p).fetchone()
    if not r:
        abort(404)
    db().execute("DELETE FROM restorations WHERE id=?", (rid,))
    db().commit()
    flash("Qeyd silindi.", "ok")
    return redirect(request.referrer or url_for("index"))


@app.route("/buraxma/<int:aid>/edit", methods=["GET", "POST"])
@login_required()
def absence_edit(aid):
    w, p = school_scope("s")
    a = db().execute(
        f"""SELECT a.*, s.soyad, s.ad, s.ata_adi, s.sinif, s.mekteb FROM absences a
            JOIN students s ON s.id=a.student_id WHERE a.id=? AND {w}""", [aid] + p).fetchone()
    if not a:
        abort(404)
    if request.method == "POST":
        tarix = request.form.get("tarix", "")
        nov = request.form.get("nov", "")
        try:
            date.fromisoformat(tarix)
        except ValueError:
            flash("Tarix düzgün deyil.", "err")
            return render_template_string(T["absence_edit.html"], a=a)
        if nov not in NOVLER:
            abort(400)
        d = db()
        d.execute("DELETE FROM absences WHERE student_id=? AND tarix=? AND id!=?", (a["student_id"], tarix, aid))
        d.execute("UPDATE absences SET tarix=?, nov=?, qeyd=? WHERE id=?",
                  (tarix, nov, clean(request.form.get("qeyd"))[:200], aid))
        d.commit()
        flash("Qeyd yeniləndi.", "ok")
        return redirect(url_for("student_view", sid=a["student_id"]))
    return render_template_string(T["absence_edit.html"], a=a)


@app.route("/shagird/<int:sid>/edit", methods=["GET", "POST"])
@login_required()
def student_edit(sid):
    s = get_student(sid)
    f = dict(s)
    if request.method == "POST":
        keys = ("soyad", "ad", "ata_adi", "mekteb", "utis", "fin", "sinif")
        f = {k: clean(request.form.get(k)) for k in keys}
        if g.user["role"] != "admin":
            f["mekteb"] = s["mekteb"]
        f["fin"] = f["fin"].upper()
        err = None
        if not all(f.values()):
            err = "Bütün xanaları doldurun."
        elif not re.fullmatch(r"[A-Z0-9]{7}", f["fin"]):
            err = "FİN kod 7 simvoldan (hərf və rəqəm) ibarət olmalıdır."
        elif not f["utis"].isdigit():
            err = "UTİS kod yalnız rəqəmlərdən ibarət olmalıdır."
        if err:
            flash(err, "err")
        else:
            try:
                db().execute("UPDATE students SET soyad=?,ad=?,ata_adi=?,mekteb=?,utis=?,fin=?,sinif=? WHERE id=?",
                             [f[k] for k in keys] + [sid])
                db().commit()
                flash("Şagirdin məlumatları yeniləndi.", "ok")
                return redirect(url_for("student_view", sid=sid))
            except sqlite3.IntegrityError:
                flash("Bu FİN kodlu başqa şagird artıq qeydiyyatdadır.", "err")
    return render_template_string(T["student_edit.html"], f=f, s=s)


# ---------------------------------------------------------------- admin: istifadəçilər
@app.route("/istifadeciler", methods=["GET", "POST"])
@login_required(admin=True)
def users():
    if request.method == "POST":
        act = request.form.get("act")
        if act == "add":
            un = clean(request.form.get("username")).lower()
            pw = request.form.get("password", "")
            mk = clean(request.form.get("mekteb"))
            if not un or not mk or len(pw) < 8:
                flash("İstifadəçi adı, məktəb və ən azı 8 simvolluq şifrə lazımdır.", "err")
            else:
                try:
                    db().execute("INSERT INTO users(username,pw,role,mekteb,ad) VALUES(?,?,?,?,?)",
                                 (un, generate_password_hash(pw), "muellim", mk,
                                  clean(request.form.get("ad")) or un))
                    db().commit()
                    flash("Direktor hesabı yaradıldı.", "ok")
                except sqlite3.IntegrityError:
                    flash("Bu istifadəçi adı artıq var.", "err")
        elif act == "reset":
            pw = request.form.get("password", "")
            if len(pw) < 8:
                flash("Şifrə ən azı 8 simvol olmalıdır.", "err")
            else:
                db().execute("UPDATE users SET pw=? WHERE id=? AND role!='admin'",
                             (generate_password_hash(pw), request.form.get("uid")))
                db().commit()
                flash("Şifrə yeniləndi.", "ok")
        elif act == "delete":
            db().execute("DELETE FROM users WHERE id=? AND role!='admin'", (request.form.get("uid"),))
            db().commit()
            flash("Hesab silindi.", "ok")
        return redirect(url_for("users"))
    rows = db().execute("SELECT * FROM users ORDER BY role, mekteb, username").fetchall()
    return render_template_string(T["users.html"], rows=rows)


# ---------------------------------------------------------------- şablonlar
T = {}

T["base.html"] = """<!doctype html>
<html lang="az"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{% block title %}Gəncə-Daşkəsən RTİ Şagird Davamiyyət Portalı{% endblock %}</title>
<style>
:root{color-scheme:light;--bg:#dce6f3;--card:#fff;--ink:#1e293b;--mut:#64748b;--line:#c3d1e4;--head:#e8f0fb;--hover:#eaf2fe;--btn:#2563eb;--g:#16a34a;--n0:#e5484d;--n1:#d97706;--n2:#7c5cdb;--err:#d92d20;--ok:#16a34a}
*{box-sizing:border-box}
[hidden]{display:none!important}
body{margin:0;font:15px/1.5 "Segoe UI",system-ui,-apple-system,Roboto,sans-serif;background:#dce6f3 linear-gradient(180deg,#c6d8ef,#dce6f3 380px) no-repeat;color:var(--ink);min-height:100vh;display:flex;flex-direction:column}
header{background:linear-gradient(100deg,#1e40af 0%,#2563eb 50%,#0891b2 100%);color:#fff;padding:.75rem 1.2rem;display:flex;flex-wrap:wrap;align-items:center;gap:.3rem;box-shadow:0 4px 14px rgba(30,64,175,.35)}
header a{color:#e0ecff;text-decoration:none;padding:.45rem .9rem;border-radius:999px;font-weight:600;font-size:.93rem}
header a:hover{background:rgba(255,255,255,.18);color:#fff}
header a.on{background:#fff;color:#1d4ed8}
header a.brand{display:flex;align-items:center;gap:.75rem;color:#fff;font-weight:800;font-size:1.1rem;line-height:1.2;margin-right:auto;padding:.2rem .5rem .2rem 0}
header a.brand:hover{background:none}
header a.brand::before{content:"";flex:none;width:38px;height:38px;border-radius:11px;background:#fff url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath d='M5 12.5l4.5 4.5L19 7.5' fill='none' stroke='%232563eb' stroke-width='3' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E") center/70% no-repeat;box-shadow:0 2px 6px rgba(0,0,0,.2)}
header a.brand small{display:block;font-weight:600;font-size:.82rem;opacity:.92}
header a.me{font-weight:500;font-size:.88rem}
main{max-width:1180px;width:100%;flex:1;margin:1.4rem auto;padding:0 1.2rem}
footer{text-align:center;color:var(--mut);font-size:.82rem;padding:1rem}
h1{font-size:1.5rem;font-weight:800;margin:.1rem 0 1rem;letter-spacing:-.01em}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:1.1rem;margin-bottom:1rem;box-shadow:0 2px 10px rgba(30,64,120,.12)}
.card.flush{padding:0;overflow:hidden}
.scroll{overflow-x:auto}
table.grid,table{width:100%;border-collapse:collapse}
.grid th,.grid td,table th,table td{border-bottom:1px solid var(--line);padding:.6rem .85rem;text-align:left;vertical-align:middle}
.grid td+td,.grid th+th{border-left:1px solid #dbe5f2}
.grid thead th,table th{background:var(--head);color:var(--mut);font-weight:700;font-size:.82rem}
.grid tbody tr:last-child td{border-bottom:0}
.grid tbody tr:hover{background:var(--hover)}
.num{width:2.8rem;text-align:right!important;color:var(--mut);font-variant-numeric:tabular-nums}
.grid td a{color:var(--btn);font-weight:600;text-decoration:none}
.grid td a:hover{text-decoration:underline}
label{display:block;font-weight:600;font-size:.84rem;margin:.55rem 0 .25rem;color:var(--mut)}
input,select,textarea{width:100%;padding:.55rem .7rem;border:1px solid #b4c5dc;border-radius:9px;background:#fff;color:var(--ink);font:inherit}
.grid input{min-width:90px;padding:.42rem .55rem}
.addrow td{background:#f3f8ff}
input:focus,select:focus,textarea:focus{outline:0;border-color:var(--btn);box-shadow:0 0 0 3px rgba(37,99,235,.15)}
button:focus-visible,a:focus-visible{outline:2px solid var(--btn);outline-offset:2px}
.row{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:.7rem;align-items:end}
.bar2{display:flex;flex-wrap:wrap;gap:.9rem;align-items:end}
.bar2>div{min-width:150px}
.bar2 .sum{margin-left:auto;color:var(--mut)}
#cnt,.sum b{font-size:1.7rem;color:var(--n0);font-weight:800;margin-right:.35rem}
button,.btn{display:inline-block;padding:.55rem 1.1rem;border:0;border-radius:9px;background:var(--btn);color:#fff;font:inherit;font-weight:600;cursor:pointer;text-decoration:none;box-shadow:0 1px 2px rgba(37,99,235,.3)}
button:hover,.btn:hover{filter:brightness(1.07)}
.btn.alt,button.alt{background:#fff;color:var(--btn);border:1px solid #c5d6f5;box-shadow:none}
.btn.warn,button.warn{background:var(--n0)}
button.link{background:none;color:var(--err);padding:0;font-weight:500;text-decoration:underline;box-shadow:none}
.seg{display:inline-flex;gap:.3rem}
.seg button{background:#fff;color:var(--mut);border:1px solid var(--line);border-radius:999px;padding:.3rem .85rem;font-weight:600;font-size:.88rem;box-shadow:none}
.seg button:hover{background:var(--hover);filter:none}
.seg button.on{color:#fff;border-color:transparent}
.seg .g.on{background:var(--g)}.seg .n0.on{background:var(--n0)}.seg .n1.on{background:var(--n1)}.seg .n2.on{background:var(--n2)}
tr.r0{background:#fff3f3}tr.r1{background:#fff8ea}tr.r2{background:#f5f2ff}
tr.r0:hover{background:#ffeaea}tr.r1:hover{background:#fff1d6}tr.r2:hover{background:#ece6ff}
.msg{width:8rem;color:var(--ok);font-weight:700;font-size:.88rem}.msg.bad{color:var(--err)}
.flash{padding:.7rem 1rem;border-radius:10px;margin-bottom:.9rem;border:1px solid;background:#fff}
.flash.ok{color:#166534;border-color:#86d7a3;background:#f0fbf4}.flash.err{color:#991b1b;border-color:#f3b1ad;background:#fff4f3}
.mut{color:var(--mut)}.tag{font-size:.82rem;padding:.12rem .6rem;border-radius:999px;background:#fff0f0;color:var(--n0);font-weight:600;white-space:nowrap}
.bar{display:flex;flex-wrap:wrap;gap:.6rem;margin-bottom:1rem}
.big{font-size:2.3rem;font-weight:800;color:var(--n0);line-height:1}
.empty{padding:2.2rem 1rem;text-align:center;color:var(--mut)}
h2{font-size:1.1rem;font-weight:800;margin:1.5rem 0 .6rem}
.cnt{background:#fff0f0;color:var(--n0);border-radius:999px;padding:.05rem .65rem;margin-left:.4rem;font-size:.95rem}
.sw{position:relative}
.sugg{position:absolute;left:0;right:0;top:100%;margin-top:4px;background:#fff;border:1px solid var(--line);border-radius:10px;box-shadow:0 10px 28px rgba(16,24,40,.14);z-index:5;overflow:hidden}
.sugg button{display:flex;justify-content:space-between;gap:1rem;width:100%;background:#fff;color:var(--ink);border:0;border-radius:0;box-shadow:none;text-align:left;font-weight:500;padding:.65rem .9rem}
.sugg button:hover{background:var(--hover);filter:none}
.sugg .none{padding:.7rem .9rem;color:var(--mut)}
.chosen{display:flex;gap:.8rem;align-items:center;justify-content:space-between;padding:.8rem 1rem;border:1px solid #b7e2c6;background:#f0fbf4;border-radius:12px}
.chosen b{font-size:1.05rem}
.chosen .alt{padding:.4rem .9rem}
.pills{display:flex;gap:.4rem;flex-wrap:wrap}
label.pill{position:relative;margin:0;display:inline-block}
.pill input{position:absolute;opacity:0;width:1px;height:1px}
.pill span{display:inline-block;padding:.5rem .95rem;border:1px solid #d3dbe6;border-radius:999px;font-weight:600;color:var(--mut);cursor:pointer;background:#fff}
.pill input:checked+span{background:var(--n0);color:#fff;border-color:transparent}
.pill input:focus-visible+span{outline:2px solid var(--btn);outline-offset:2px}
.go{font-size:1.05rem;padding:.75rem 1.4rem;margin-top:.6rem}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:.8rem}
.tag.ok{background:#e9f8ef;color:var(--g)}
.acts{display:flex;gap:.6rem;flex-wrap:wrap;align-items:center}
.info{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:.9rem;margin-bottom:.9rem}
.info .k{color:var(--mut);font-size:.8rem;font-weight:600}
.entry{padding:1.4rem}
.tabs{display:inline-flex;background:#eaf0f9;border-radius:12px;padding:4px;gap:4px;margin-bottom:1.3rem}
.tabs label{margin:0;position:relative}
.tabs input{position:absolute;opacity:0;width:1px;height:1px}
.tabs span{display:block;padding:.55rem 1.3rem;border-radius:9px;font-weight:700;color:var(--mut);cursor:pointer}
.tabs input:checked+span{background:#fff;box-shadow:0 1px 5px rgba(30,64,120,.2)}
.tabs input[value=yayindi]:checked+span{color:var(--n0)}
.tabs input[value=berpa]:checked+span{color:var(--g)}
.tabs input:focus-visible+span{outline:2px solid var(--btn)}
.fld{margin-bottom:1.2rem}
.fld>label,.g3 label{margin:0 0 .4rem}
.entry input:not([type=radio]),.entry select{height:46px}
.entry .srch{padding-left:2.7rem;background:#fff url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%2364748b' stroke-width='2.2' stroke-linecap='round'%3E%3Ccircle cx='11' cy='11' r='7'/%3E%3Cpath d='M20 20l-3.5-3.5'/%3E%3C/svg%3E") 14px center/20px no-repeat}
.hint{margin-top:.6rem;color:var(--mut);font-size:.9rem}
.linkbtn{background:none;border:0;box-shadow:none;padding:0;color:var(--btn);font:inherit;font-weight:700;cursor:pointer}
.linkbtn:hover{text-decoration:underline;filter:none}
.newbox{background:#f4f8fe;border:1px dashed #a9bddb;border-radius:12px;padding:1rem 1rem 1.1rem}
.nbhead{display:flex;justify-content:space-between;align-items:center;margin-bottom:.3rem}
.g3{display:grid;grid-template-columns:minmax(190px,1fr) minmax(0,1.7fr) minmax(0,1.7fr);gap:1rem;align-items:start}
.entry .pills span{display:inline-flex;align-items:center;height:46px;padding:0 1.05rem}
.foot{margin-top:1.4rem;display:flex}
.entry .go{margin:0;min-width:300px;height:50px}
.go.gr{background:var(--g);box-shadow:0 1px 2px rgba(22,163,74,.35)}
.cardhead{padding:1rem 1.1rem .7rem}.cardhead h3{margin:0}
.two{display:grid;grid-template-columns:minmax(0,2fr) minmax(270px,1fr);gap:1rem;align-items:start}
.card h3{margin:0 0 .7rem;font-size:1rem;font-weight:800}
.mini{display:flex;gap:2.2rem}
.chart{display:flex;align-items:flex-end;gap:5px;height:160px}
.chart .col{flex:1;display:flex;flex-direction:column;justify-content:flex-end;align-items:center;height:100%}
.chart i{display:block;width:100%;background:linear-gradient(180deg,#3b82f6,#06b6d4);border-radius:5px 5px 0 0;min-height:3px}
.chart .v{font-size:.72rem;font-weight:700;color:var(--btn);height:1em}
.chart .l{font-size:.64rem;color:var(--mut);margin-top:4px}
.top{margin:0;padding:0;list-style:none}
.top li{display:flex;justify-content:space-between;gap:.8rem;padding:.55rem 0;border-bottom:1px solid var(--line)}
.top li:last-child{border:0}
.top b{background:#fff0f0;color:var(--n0);border-radius:999px;padding:0 .65rem;height:1.5rem}
.hero{display:grid;grid-template-columns:1.2fr 1fr;gap:1.5rem;margin-top:1rem}
.intro{background:linear-gradient(135deg,#1e40af,#0891b2);color:#fff;border-radius:18px;padding:2.2rem;box-shadow:0 8px 24px rgba(30,64,175,.3)}
.intro h1{font-size:1.9rem;color:#fff;margin-bottom:.6rem}
.intro p{margin:0 0 1rem;font-size:1.05rem;opacity:.95}
.feat{background:rgba(255,255,255,.15);border-radius:12px;padding:.8rem 1rem;margin-top:.7rem}
.feat b{display:block}
.logincard{align-self:center;padding:2rem}
.logincard h2{margin:0 0 .5rem;font-size:1.4rem}
@media(max-width:860px){.two,.hero,.g3{grid-template-columns:1fr}.entry .go{width:100%;min-width:0}}
@media(max-width:700px){.seg button{padding:.3rem .55rem}.grid th,.grid td{padding:.45rem .5rem}header{padding:.4rem .6rem}}
@media print{header,.noprint,.flash{display:none!important}body{background:#fff}.card{border:0;padding:0;box-shadow:none}main{max-width:none}.seg button:not(.on){display:none}}
</style></head><body>
<header class="noprint">
<a class="brand" href="{{ url_for('index') }}"><span>Gəncə-Daşkəsən RTİ<small>Şagird Davamiyyət Portalı</small></span></a>
{% if user %}
<a href="{{ url_for('index') }}"{% if request.endpoint in ('index','school') %} class="on"{% endif %}>Məktəblər</a>
<a href="{{ url_for('qeyd_form') }}"{% if request.endpoint in ('qeyd_form','jurnal') %} class="on"{% endif %}>Qeyd et</a>
<a href="{{ url_for('students') }}"{% if request.endpoint in ('students','student_new','student_view','student_edit','absence_edit') %} class="on"{% endif %}>Şagirdlər</a>
{% if user.role=='admin' %}<a href="{{ url_for('users') }}"{% if request.endpoint=='users' %} class="on"{% endif %}>Direktorlar</a>{% endif %}
<a class="me" href="{{ url_for('change_password') }}">{{ user.ad }}</a>
<a href="{{ url_for('logout') }}">Çıxış</a>
{% endif %}
</header>
<main>
{% with m = get_flashed_messages(with_categories=true) %}{% for c,t in m %}<div class="flash {{ c }}" role="status">{{ t }}</div>{% endfor %}{% endwith %}
{% block body %}{% endblock %}
</main>
<footer class="noprint">Gəncə-Daşkəsən Regional Təhsil İdarəsi</footer></body></html>"""

T["macros.html"] = """{% macro chart(days) %}<div class="chart">{% for d in days %}<div class="col" title="{{ d.full }}: {{ d.n }}"><span class="v">{{ d.n if d.n else '' }}</span><i style="height:{{ d.h }}px"></i><span class="l">{{ d.l }}</span></div>{% endfor %}</div>{% endmacro %}
{% macro toplist(top, mk=false) %}{% if top %}<ol class="top">{% for t in top %}<li><span>{{ t.soyad }} {{ t.ad }} <small class="mut">{{ t.sinif }}{% if mk %}, {{ t.mekteb }}{% endif %}</small></span><b>{{ t.c }}</b></li>{% endfor %}</ol>{% else %}<p class="mut">Bu ay hələ qeyd yoxdur.</p>{% endif %}{% endmacro %}"""

T["login.html"] = """{% extends 'base.html' %}{% block body %}
<div class="hero">
<section class="intro">
<h1>Şagird Davamiyyət Portalı</h1>
<p>Məktəblərdə dərsdən yayınan şagirdlərin vahid, təhlükəsiz və operativ qeydiyyatı.</p>
<div class="feat"><b>Direktorlar üçün</b>Şagirdin adını yazın, səbəbi seçin və bir düymə ilə qeyd edin.</div>
<div class="feat"><b>Rəhbərlik üçün</b>Bütün məktəblər üzrə canlı statistika və hər şagirdin tam tarixçəsi.</div>
<div class="feat"><b>İstənilən vaxt</b>Hesabatı Excel formatında bir kliklə endirin və çap edin.</div>
</section>
<section class="card logincard"><h2>Daxil ol</h2>
<form method="post"><input type="hidden" name="csrf" value="{{ csrf }}">
<label for="u">İstifadəçi adı</label><input id="u" name="username" autocomplete="username" autofocus required>
<label for="p">Şifrə</label><input id="p" type="password" name="password" autocomplete="current-password" required>
<p><button class="go" style="width:100%">Daxil ol</button></p></form>
<p class="mut" style="margin:0">Hesabınız yoxdursa, idarənin administratoruna müraciət edin.</p></section>
</div>{% endblock %}"""

T["password.html"] = """{% extends 'base.html' %}{% block body %}
<div class="card" style="max-width:420px"><h1>Şifrəni dəyiş</h1>
<form method="post"><input type="hidden" name="csrf" value="{{ csrf }}">
<label for="o">Köhnə şifrə</label><input id="o" type="password" name="old" required>
<label for="n">Yeni şifrə (ən azı 8 simvol)</label><input id="n" type="password" name="new" minlength="8" required>
<p><button>Şifrəni saxla</button></p></form></div>{% endblock %}"""

T["qeyd.html"] = """{% extends 'base.html' %}{% block body %}
<div class="bar2" style="align-items:center;margin-bottom:1rem"><h1 style="margin:0">Qeyd et</h1>
<a class="btn alt" style="margin-left:auto" href="{{ url_for('jurnal') }}">Sinif jurnalı</a></div>
<form method="post" action="{{ url_for('qeyd') }}" class="card entry" id="qf" autocomplete="off">
<input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="sid" id="sid">
<div class="tabs" role="radiogroup" aria-label="Hadisənin növü">
<label><input type="radio" name="act" value="yayindi" checked><span>Dərsdən yayındı</span></label>
<label><input type="radio" name="act" value="berpa"><span>Bərpa olundu</span></label></div>

<div class="fld"><label>Şagird</label>
<div id="pick"><div class="sw"><input id="ax" class="srch" placeholder="Soyad və ya adı yazın, məsələn: Əliyev" aria-label="Şagirdi axtar" autofocus><div id="res" class="sugg" hidden></div></div>
<div class="hint only-y">Siyahıda yoxdur? <button type="button" class="linkbtn" id="shownew">+ Yeni şagird əlavə et</button></div></div>
<div id="chosen" class="chosen" hidden><div><b id="cname"></b><div class="mut" id="cmeta"></div></div><button type="button" class="alt" id="clr">Dəyiş</button></div>
<div id="newbox" class="newbox" hidden>
<div class="nbhead"><b>Yeni şagird</b><button type="button" class="linkbtn" id="hidenew">Siyahıdan seç</button></div>
<div class="row">
<div><label for="soyad">Soyadı</label><input class="nf" id="soyad" name="soyad" value="{{ f.soyad }}"></div>
<div><label for="ad">Adı</label><input class="nf" id="ad" name="ad" value="{{ f.ad }}"></div>
<div><label for="ata">Ata adı</label><input class="nf" id="ata" name="ata_adi" value="{{ f.ata_adi }}"></div>
{% if user.role=='admin' %}<div><label for="mk">Məktəb</label><input class="nf" id="mk" name="mekteb" value="{{ f.mekteb }}"></div>{% endif %}
<div><label for="sinif">Sinif</label><input class="nf" id="sinif" name="sinif" value="{{ f.sinif }}" placeholder="7-A"></div>
<div><label for="utis">UTİS kodu</label><input class="nf" id="utis" name="utis" value="{{ f.utis }}" inputmode="numeric"></div>
<div><label for="fin">FİN kodu</label><input class="nf" id="fin" name="fin" value="{{ f.fin }}" maxlength="7" style="text-transform:uppercase"></div>
</div></div></div>

<div class="g3">
<div><label id="tl" for="t">Yayınma tarixi</label><input id="t" type="date" name="tarix" value="{{ today }}" max="{{ today }}" required></div>
<div class="only-y"><label>Səbəb</label><div class="pills">{% for n in NOVLER %}<label class="pill"><input type="radio" name="nov" value="{{ n }}"{% if loop.first %} checked{% endif %}><span>{{ NOVSHORT[n] }}</span></label>{% endfor %}</div></div>
<div class="only-y"><label for="q">Görülən tədbir <span class="mut">(istəyə bağlı)</span></label><input id="q" name="qeyd" maxlength="200" placeholder="məsələn: valideynlə danışıldı"></div>
</div>
<div class="foot"><button class="go" id="sub">Dərsdən yayındı kimi qeyd et</button></div>
</form>

<div class="card flush"><div class="cardhead"><h3>Bu gün qeyd edilənlər <span class="cnt">{{ rows|length }}</span></h3></div>
{% if rows %}<div class="scroll"><table class="grid"><thead><tr><th class="num">№</th><th>Şagird</th><th>Sinif</th>{% if user.role=='admin' %}<th>Məktəb</th>{% endif %}<th>Hadisə</th><th>Görülən tədbir</th><th></th></tr></thead><tbody>
{% for r in rows %}<tr><td class="num">{{ loop.index }}</td><td><a href="{{ url_for('student_view', sid=r.student_id) }}">{{ r.soyad }} {{ r.ad }} {{ r.ata_adi }}</a></td><td>{{ r.sinif }}</td>{% if user.role=='admin' %}<td>{{ r.mekteb }}</td>{% endif %}<td><span class="tag{% if r.tip=='b' %} ok{% endif %}">{{ r.nov }}</span></td><td>{{ r.qeyd }}</td>
<td><form method="post" action="{% if r.tip=='b' %}{{ url_for('restore_delete', rid=r.id) }}{% else %}{{ url_for('absence_delete', aid=r.id) }}{% endif %}" onsubmit="return confirm('Bu qeyd silinsin?')"><input type="hidden" name="csrf" value="{{ csrf }}"><button class="link">Sil</button></form></td></tr>{% endfor %}</tbody></table></div>
{% else %}<div class="empty">Bu gün hələ heç kim qeyd edilməyib.</div>{% endif %}</div>
<script>
const $=id=>document.getElementById(id),ax=$('ax'),res=$('res'),sid=$('sid'),nf=document.querySelectorAll('.nf');let tm;
const mode=()=>document.querySelector('input[name=act]:checked').value;
function setNew(on){$('newbox').hidden=!on;$('pick').hidden=on;nf.forEach(i=>i.required=on);if(on){sid.value='';$('chosen').hidden=true;$('soyad').focus()}else ax.focus()}
function choose(id,name,meta){sid.value=id;$('cname').textContent=name;$('cmeta').textContent=meta;$('chosen').hidden=false;$('pick').hidden=true;res.hidden=true;$('t').focus()}
function applyMode(){const b=mode()==='berpa';if(b&&!$('newbox').hidden)setNew(false);
 document.querySelectorAll('.only-y').forEach(e=>e.hidden=b);$('tl').textContent=b?'Bərpa tarixi':'Yayınma tarixi';
 const sb=$('sub');sb.textContent=b?'Bərpa olundu kimi qeyd et':'Dərsdən yayındı kimi qeyd et';sb.classList.toggle('gr',b)}
ax.addEventListener('input',()=>{clearTimeout(tm);tm=setTimeout(async()=>{
 const q=ax.value.trim();if(q.length<2){res.hidden=true;return}
 const r=await (await fetch("{{ url_for('api_search') }}?q="+encodeURIComponent(q))).json();
 res.innerHTML='';
 if(!r.r.length){const d=document.createElement('div');d.className='none';d.textContent='Tapılmadı. "Yeni şagird əlavə et" düyməsini basın.';res.appendChild(d)}
 r.r.forEach(x=>{const meta=(x.mekteb?x.mekteb+', ':'')+x.sinif+' sinif';const b=document.createElement('button');b.type='button';const a=document.createElement('span');a.textContent=x.ad;const c=document.createElement('span');c.className='mut';c.textContent=meta;b.append(a,c);b.onclick=()=>choose(x.id,x.ad,meta);res.appendChild(b)});
 res.hidden=false},200)});
ax.addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();const b=res.querySelector('button');if(b)b.click()}});
$('clr').onclick=()=>{sid.value='';$('chosen').hidden=true;$('pick').hidden=false;ax.value='';ax.focus()};
$('shownew').onclick=()=>setNew(true);
$('hidenew').onclick=()=>setNew(false);
document.querySelectorAll('input[name=act]').forEach(r=>r.addEventListener('change',applyMode));
$('qf').addEventListener('submit',e=>{if(!sid.value&&$('newbox').hidden){e.preventDefault();ax.focus();alert('Əvvəlcə şagirdi siyahıdan seçin.')}});
applyMode();{% if new %}setNew(true);{% endif %}
</script>{% endblock %}"""

T["dash.html"] = """{% extends 'base.html' %}{% from 'macros.html' import chart, toplist %}{% block body %}
<div class="bar2" style="align-items:center;margin-bottom:1rem"><h1 style="margin:0">Məktəblər</h1>
<a class="btn go" style="margin:0 0 0 auto" href="{{ url_for('qeyd_form') }}">Dərsdən yayınanı qeyd et</a></div>
<div class="stats">
<div class="card"><div class="big">{{ rows|length }}</div><div class="mut">məktəb</div></div>
<div class="card"><div class="big">{{ tot.sagird }}</div><div class="mut">şagird qeydiyyatda</div></div>
<div class="card"><div class="big">{{ tot.bugun }}</div><div class="mut">bu gün yayınıb</div></div>
<div class="card"><div class="big">{{ tot.ay }}</div><div class="mut">bu ay yayınıb</div></div>
</div>
<div class="two"><div class="card"><h3>Son 14 gün{% if user.role=='admin' %}, bütün məktəblər{% endif %}</h3>{{ chart(side.days) }}</div>
<div class="card"><h3>Bu ay ən çox yayınanlar</h3>{{ toplist(side.top, user.role=='admin') }}</div></div>
<form class="card bar2" action="{{ url_for('absences_csv') }}">
{% if user.role=='admin' %}<div><label for="m">Məktəb</label><select id="m" name="mekteb"><option value="">Bütün məktəblər</option>{% for m in mektebler %}<option>{{ m }}</option>{% endfor %}</select></div>{% endif %}
<div><label for="d1">Başlanğıc tarix</label><input id="d1" type="date" name="d1"></div>
<div><label for="d2">Son tarix</label><input id="d2" type="date" name="d2"></div>
<div><button>Excel-ə endir</button></div>
</form>
<div class="card flush scroll">
{% if rows %}<table class="grid"><thead><tr><th>Məktəb</th><th>Şagird</th><th>Direktor hesabı</th><th>Bu gün</th><th>Bu ay</th><th>Cəmi yayınma</th><th></th></tr></thead><tbody>
{% for r in rows %}<tr><td><a href="{{ url_for('school', ad=r.m) }}">{{ r.m }}</a></td><td>{{ r.sagird }}</td><td>{{ r.muellim }}</td><td>{{ r.bugun }}</td><td>{{ r.ay }}</td><td>{{ r.cemi }}</td>
<td><a href="{{ url_for('absences_csv', mekteb=r.m) }}">Endir</a></td></tr>{% endfor %}</tbody></table>
{% else %}<div class="empty">Hələ məktəb yoxdur. "Direktorlar" bölməsində hər məktəb üçün direktor hesabı yaradın.</div>{% endif %}</div>
<h2>Son qeydlər</h2>
<div class="card flush scroll">{% if recent %}<table class="grid"><thead><tr><th>Tarix</th><th>Şagird</th><th>Sinif</th><th>Məktəb</th><th>Səbəb</th><th>Qeyd edən</th></tr></thead><tbody>
{% for r in recent %}<tr><td>{{ r.tarix|azd }}</td><td>{{ r.soyad }} {{ r.ad }}</td><td>{{ r.sinif }}</td><td>{{ r.mekteb }}</td><td><span class="tag">{{ r.nov }}</span></td><td>{{ r.qeyd_eden }}</td></tr>{% endfor %}</tbody></table>
{% else %}<div class="empty">Hələ qeyd yoxdur.</div>{% endif %}</div>
{% endblock %}"""

T["school.html"] = """{% extends 'base.html' %}{% block body %}
<h1>{{ ad }}</h1>
<div class="bar noprint"><a class="btn" href="{{ url_for('absences_csv', mekteb=ad) }}">Excel-ə endir</a>
<a class="btn alt" href="{{ url_for('index') }}">Məktəblər</a></div>
<div class="card flush scroll">
{% if rows %}<table class="grid"><thead><tr><th class="num">№</th><th>Soyadı</th><th>Adı</th><th>Ata adı</th><th>Sinif</th><th>UTİS</th><th>FİN</th><th>Yayınma sayı</th><th>o cümlədən üzrsüz</th><th>Son buraxma</th></tr></thead><tbody>
{% for s in rows %}<tr><td class="num">{{ loop.index }}</td><td><a href="{{ url_for('student_view', sid=s.id) }}">{{ s.soyad }}</a></td><td>{{ s.ad }}</td><td>{{ s.ata_adi }}</td><td>{{ s.sinif }}</td><td>{{ s.utis }}</td><td>{{ s.fin|mask_fin }}</td><td>{{ s.say }}</td><td>{{ s.uzrsuz }}</td><td>{{ s.son|azd }}</td></tr>{% endfor %}</tbody></table>
{% else %}<div class="empty">Bu məktəbdə şagird yoxdur.</div>{% endif %}</div>
{% endblock %}"""

T["students.html"] = """{% extends 'base.html' %}{% block body %}
<h1>Şagirdlər</h1>
<form class="card bar2 noprint">
<div style="flex:1"><label for="q">Axtarış</label><input id="q" name="q" value="{{ q }}" placeholder="Soyad, ad, UTİS, FİN"></div>
<div><label for="s">Sinif</label><input id="s" name="sinif" value="{{ sinif }}" placeholder="məs. 7-A"></div>
<div><button>Axtar</button></div>
<div><a class="btn alt" href="{{ url_for('absences_csv', q=q, sinif=sinif) }}">Excel-ə endir</a></div></form>
<form id="addf" method="post" action="{{ url_for('student_new') }}"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="next" value="list"></form>
<div class="card flush scroll"><table class="grid">
<thead><tr><th class="num">№</th><th>Soyadı</th><th>Adı</th><th>Ata adı</th>{% if user.role=='admin' %}<th>Məktəb</th>{% endif %}<th>Sinif</th><th>UTİS kodu</th><th>FİN kodu</th><th>Yayınma</th><th>Son yayınma</th><th></th></tr></thead>
<tbody>
<tr class="addrow noprint"><td class="num">+</td>
<td><input form="addf" name="soyad" placeholder="Soyadı" required></td>
<td><input form="addf" name="ad" placeholder="Adı" required></td>
<td><input form="addf" name="ata_adi" placeholder="Ata adı" required></td>
{% if user.role=='admin' %}<td><input form="addf" name="mekteb" placeholder="Məktəb" required></td>{% endif %}
<td><input form="addf" name="sinif" value="{{ sinif }}" placeholder="7-A" style="min-width:60px" required></td>
<td><input form="addf" name="utis" inputmode="numeric" placeholder="UTİS" required></td>
<td><input form="addf" name="fin" maxlength="7" placeholder="FİN" style="text-transform:uppercase" required></td>
<td></td><td></td><td><button form="addf">Əlavə et</button></td></tr>
{% for s in rows %}<tr><td class="num">{{ loop.index }}</td>
<td><a href="{{ url_for('student_view', sid=s.id) }}">{{ s.soyad }}</a></td><td><a href="{{ url_for('student_view', sid=s.id) }}">{{ s.ad }}</a></td><td>{{ s.ata_adi }}</td>
{% if user.role=='admin' %}<td>{{ s.mekteb }}</td>{% endif %}<td>{{ s.sinif }}</td><td>{{ s.utis }}</td><td>{{ s.fin|mask_fin }}</td>
<td>{{ s.say }}</td><td>{{ s.son|azd }}</td><td><a href="{{ url_for('student_view', sid=s.id) }}">Aç</a></td></tr>{% endfor %}
</tbody></table>
{% if not rows %}<div class="empty">Şagird tapılmadı. Yuxarıdakı sətirdə məlumatı yazıb Enter basın.</div>{% endif %}
</div>{% endblock %}"""

T["jurnal.html"] = """{% extends 'base.html' %}{% block body %}
<h1>Sinif jurnalı</h1>
<form class="card bar2 noprint">
{% if user.role=='admin' %}<div><label for="m">Məktəb</label><select id="m" name="mekteb" onchange="this.form.sinif.value='';this.form.submit()"><option value="">Seçin</option>{% for m in mektebler %}<option {% if m==mekteb %}selected{% endif %}>{{ m }}</option>{% endfor %}</select></div>{% endif %}
<div><label for="s">Sinif</label><select id="s" name="sinif" onchange="this.form.submit()"><option value="">Seçin</option>{% for c in siniflar %}<option {% if c==sinif %}selected{% endif %}>{{ c }}</option>{% endfor %}</select></div>
<div><label for="t">Tarix</label><input id="t" type="date" name="tarix" value="{{ tarix }}" max="{{ today }}" onchange="this.form.submit()"></div>
<div class="sum"><span id="cnt">0</span>nəfər yayınıb</div>
<div><button type="button" class="alt" onclick="window.print()">Çap et</button></div>
</form>
{% if rows %}
<div class="card flush scroll"><table class="grid" id="jt">
<thead><tr><th class="num">№</th><th>Soyadı, adı, ata adı</th><th>UTİS</th><th>FİN</th><th>Davamiyyət</th><th>Görülən tədbir</th><th></th></tr></thead><tbody>
{% for r in rows %}<tr data-sid="{{ r.id }}" data-nov="{{ r.nov or '' }}"{% if r.nov %} class="r{{ NOVLER.index(r.nov) }}"{% endif %}>
<td class="num">{{ loop.index }}</td><td><a href="{{ url_for('student_view', sid=r.id) }}">{{ r.soyad }} {{ r.ad }} {{ r.ata_adi }}</a></td>
<td>{{ r.utis }}</td><td>{{ r.fin|mask_fin }}</td>
<td><div class="seg"><button type="button" data-nov="" data-i="" class="g{% if not r.nov %} on{% endif %}">Gəlib</button>{% for n in NOVLER %}<button type="button" data-nov="{{ n }}" data-i="{{ loop.index0 }}" class="n{{ loop.index0 }}{% if r.nov==n %} on{% endif %}">{{ NOVSHORT[n] }}</button>{% endfor %}</div></td>
<td><input class="qeyd" value="{{ r.qeyd or '' }}" maxlength="200" placeholder="görülən tədbir" {% if not r.nov %}disabled{% endif %}></td><td class="msg"></td></tr>{% endfor %}
</tbody></table></div>
<script>
const T="{{ tarix }}",C="{{ csrf }}",tb=document.getElementById('jt');
function count(){document.getElementById('cnt').textContent=Array.from(tb.rows).filter(r=>r.dataset.nov).length}
async function save(tr,nov,qeyd,i){
 const m=tr.querySelector('.msg');m.className='msg';m.textContent='…';
 const fd=new FormData();fd.append('csrf',C);fd.append('sid',tr.dataset.sid);fd.append('tarix',T);fd.append('nov',nov||'Gəlib');fd.append('qeyd',qeyd);
 try{
  const r=await fetch("{{ url_for('api_absence') }}",{method:'POST',body:fd});if(!r.ok)throw 0;
  tr.dataset.nov=nov;tr.className=nov?'r'+i:'';
  tr.querySelectorAll('.seg button').forEach(b=>b.classList.toggle('on',b.dataset.nov===nov));
  const q=tr.querySelector('.qeyd');q.disabled=!nov;if(!nov)q.value='';
  m.textContent='✓ saxlandı';count();setTimeout(()=>{m.textContent=''},1500);
 }catch(e){m.className='msg bad';m.textContent='Xəta, təkrar basın'}
}
tb.addEventListener('click',e=>{const b=e.target.closest('.seg button');if(!b)return;const tr=b.closest('tr');
 save(tr,b.dataset.nov,b.dataset.nov?tr.querySelector('.qeyd').value:'',b.dataset.i)});
tb.addEventListener('change',e=>{if(!e.target.classList.contains('qeyd'))return;const tr=e.target.closest('tr');
 const b=tr.querySelector('.seg button.on');if(tr.dataset.nov)save(tr,tr.dataset.nov,e.target.value,b.dataset.i)});
count();
</script>
{% else %}
<div class="card empty">{% if user.role=='admin' and not mekteb %}Məktəbi, sonra sinfi seçin.{% elif not siniflar %}Bu məktəbdə hələ şagird yoxdur. "Şagirdlər" bölməsindən əlavə edin.{% elif not sinif %}Sinfi seçin.{% else %}Bu sinifdə şagird yoxdur.{% endif %}</div>
{% endif %}{% endblock %}"""

T["student_new.html"] = """{% extends 'base.html' %}{% block body %}
<h1>Yeni şagird</h1>
<form method="post" class="card" style="max-width:640px"><input type="hidden" name="csrf" value="{{ csrf }}">
<div class="row">
<div><label for="a">Soyadı</label><input id="a" name="soyad" value="{{ f.soyad }}" required></div>
<div><label for="b">Adı</label><input id="b" name="ad" value="{{ f.ad }}" required></div>
<div><label for="c">Ata adı</label><input id="c" name="ata_adi" value="{{ f.ata_adi }}" required></div></div>
<div class="row">
{% if user.role=='admin' %}<div><label for="m">Məktəb</label><input id="m" name="mekteb" value="{{ f.mekteb }}" required></div>
{% else %}<div><label>Məktəb</label><input value="{{ user.mekteb }}" disabled></div>{% endif %}
<div><label for="k">Sinif</label><input id="k" name="sinif" value="{{ f.sinif }}" placeholder="məs. 7-A" required></div></div>
<div class="row">
<div><label for="u">UTİS kodu</label><input id="u" name="utis" value="{{ f.utis }}" inputmode="numeric" required></div>
<div><label for="f">FİN kodu</label><input id="f" name="fin" value="{{ f.fin }}" maxlength="7" style="text-transform:uppercase" required></div></div>
<p><button>Saxla</button> <button class="alt" name="next" value="absence">Saxla və dərsdən yayındı qeyd et</button></p>
</form>{% endblock %}"""

T["student.html"] = """{% extends 'base.html' %}{% block body %}
<h1>{{ s.soyad }} {{ s.ad }} {{ s.ata_adi }}</h1>
<div class="two"><div>
<div class="card"><div class="info">
<div><div class="k">Məktəb</div><b>{{ s.mekteb }}</b></div><div><div class="k">Sinif</div><b>{{ s.sinif }}</b></div>
<div><div class="k">UTİS kodu</div><b>{{ s.utis }}</b></div><div><div class="k">FİN kodu</div><b>{{ s.fin }}</b></div></div>
<a class="btn alt" href="{{ url_for('student_edit', sid=s.id) }}">Məlumatları redaktə et</a>
{% if user.role=='admin' %}<form method="post" action="{{ url_for('student_delete', sid=s.id) }}" style="display:inline" onsubmit="return confirm('Şagird və bütün qeydləri silinsin?')">
<input type="hidden" name="csrf" value="{{ csrf }}"> <button class="alt">Şagirdi sil</button></form>{% endif %}</div>
<div class="card flush scroll"><div style="padding:1rem 1rem .6rem"><h3 style="margin:0">Yayınma və bərpa qeydləri <span class="cnt" style="background:#fff0f0;color:var(--n0);border-radius:999px;padding:0 .65rem">{{ n }} yayınma</span></h3></div>
{% if rows %}<table class="grid"><thead><tr><th>Tarix</th><th>Hadisə</th><th>Görülən tədbir</th><th>Qeyd edən</th><th class="noprint"></th></tr></thead><tbody>
{% for r in rows %}<tr><td>{{ r.tarix|azd }}</td><td><span class="tag{% if r.tip=='b' %} ok{% endif %}">{{ r.nov }}</span></td><td>{{ r.qeyd }}</td><td>{{ r.qeyd_eden }}</td>
<td class="noprint">{% if r.tip=='y' %}<a href="{{ url_for('absence_edit', aid=r.id) }}">Redaktə</a> &nbsp; {% endif %}<form method="post" style="display:inline" action="{% if r.tip=='b' %}{{ url_for('restore_delete', rid=r.id) }}{% else %}{{ url_for('absence_delete', aid=r.id) }}{% endif %}" onsubmit="return confirm('Bu qeyd silinsin?')"><input type="hidden" name="csrf" value="{{ csrf }}"><button class="link">Sil</button></form></td></tr>{% endfor %}</tbody></table>
{% else %}<div class="empty">Hələ qeyd yoxdur.</div>{% endif %}</div></div>
<aside>
<form method="post" action="{{ url_for('absence_new', sid=s.id) }}" class="card"><input type="hidden" name="csrf" value="{{ csrf }}">
<h3>Dərsdən yayındı</h3>
<label for="t1">Tarix</label><input id="t1" type="date" name="tarix" value="{{ today }}" max="{{ today }}" required>
<label for="n1">Səbəb</label><select id="n1" name="nov">{% for n in NOVLER %}<option>{{ n }}</option>{% endfor %}</select>
<label for="q1">Görülən tədbir</label><input id="q1" name="qeyd" maxlength="200">
<p><button class="warn">Yayındı kimi qeyd et</button></p></form>
<form method="post" action="{{ url_for('restore', sid=s.id) }}" class="card"><input type="hidden" name="csrf" value="{{ csrf }}">
<h3>Bərpa olundu</h3>
<label for="t2">Bərpa tarixi</label><input id="t2" type="date" name="tarix" value="{{ today }}" max="{{ today }}" required>
<p><button>Bərpa olundu</button></p></form>
</aside></div>{% endblock %}"""

T["student_edit.html"] = """{% extends 'base.html' %}{% block body %}
<h1>Şagirdin məlumatlarını redaktə et</h1>
<form method="post" class="card" style="max-width:640px"><input type="hidden" name="csrf" value="{{ csrf }}">
<div class="row">
<div><label for="a">Soyadı</label><input id="a" name="soyad" value="{{ f.soyad }}" required></div>
<div><label for="b">Adı</label><input id="b" name="ad" value="{{ f.ad }}" required></div>
<div><label for="c">Ata adı</label><input id="c" name="ata_adi" value="{{ f.ata_adi }}" required></div></div>
<div class="row">
{% if user.role=='admin' %}<div><label for="m">Məktəb</label><input id="m" name="mekteb" value="{{ f.mekteb }}" required></div>
{% else %}<div><label>Məktəb</label><input value="{{ s.mekteb }}" disabled></div>{% endif %}
<div><label for="k">Sinif</label><input id="k" name="sinif" value="{{ f.sinif }}" required></div></div>
<div class="row">
<div><label for="u">UTİS kodu</label><input id="u" name="utis" value="{{ f.utis }}" inputmode="numeric" required></div>
<div><label for="f">FİN kodu</label><input id="f" name="fin" value="{{ f.fin }}" maxlength="7" style="text-transform:uppercase" required></div></div>
<p><button>Saxla</button> <a class="btn alt" href="{{ url_for('student_view', sid=s.id) }}">Ləğv et</a></p>
</form>{% endblock %}"""

T["absence_edit.html"] = """{% extends 'base.html' %}{% block body %}
<h1>Qeydi redaktə et</h1>
<form method="post" class="card" style="max-width:520px"><input type="hidden" name="csrf" value="{{ csrf }}">
<p><b>{{ a.soyad }} {{ a.ad }} {{ a.ata_adi }}</b><br><span class="mut">{{ a.mekteb }}, {{ a.sinif }} sinif</span></p>
<label for="t">Tarix</label><input id="t" type="date" name="tarix" value="{{ a.tarix }}" max="{{ today }}" required>
<label for="n">Səbəb</label><select id="n" name="nov">{% for n in NOVLER %}<option{% if n==a.nov %} selected{% endif %}>{{ n }}</option>{% endfor %}</select>
<label for="q">Görülən tədbir</label><textarea id="q" name="qeyd" rows="2">{{ a.qeyd or '' }}</textarea>
<p><button>Saxla</button> <a class="btn alt" href="{{ url_for('student_view', sid=a.student_id) }}">Ləğv et</a></p></form>{% endblock %}"""

T["absence_new.html"] = """{% extends 'base.html' %}{% block body %}
<h1>Dərsdən yayındı</h1>
<form method="post" class="card" style="max-width:520px"><input type="hidden" name="csrf" value="{{ csrf }}">
<p><b>{{ s.soyad }} {{ s.ad }} {{ s.ata_adi }}</b><br><span class="mut">{{ s.mekteb }}, {{ s.sinif }} sinif</span></p>
<label for="t">Tarix</label><input id="t" type="date" name="tarix" value="{{ request.form.get('tarix', today) }}" max="{{ today }}" required>
<label for="n">Növ</label><select id="n" name="nov">{% for n in NOVLER %}<option>{{ n }}</option>{% endfor %}</select>
<label for="q">Görülən tədbir (istəyə bağlı)</label><textarea id="q" name="qeyd" rows="2"></textarea>
<p><button>Saxla</button> <a class="btn alt" href="{{ url_for('students') }}">Ləğv et</a></p></form>{% endblock %}"""

T["users.html"] = """{% extends 'base.html' %}{% block body %}
<h1>Direktor hesabları</h1>
<p class="mut">Hər məktəb üçün hesabı həmin məktəbin direktoru istifadə edir.</p>
<form method="post" class="card row"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="act" value="add">
<div><label for="a">Ad, soyad</label><input id="a" name="ad"></div>
<div><label for="u">İstifadəçi adı</label><input id="u" name="username" required></div>
<div><label for="m">Məktəb</label><input id="m" name="mekteb" required></div>
<div><label for="p">Şifrə (≥8)</label><input id="p" name="password" minlength="8" required></div>
<div><button>Hesab yarat</button></div></form>
<div class="card scroll"><table><tr><th>Ad</th><th>İstifadəçi</th><th>Rol</th><th>Məktəb</th><th>Əməliyyat</th></tr>
{% for u in rows %}<tr><td>{{ u.ad }}</td><td>{{ u.username }}</td><td>{{ 'Admin' if u.role=='admin' else 'Direktor' }}</td><td>{{ u.mekteb or '' }}</td><td>
{% if u.role!='admin' %}<form method="post" style="display:flex;gap:.4rem;flex-wrap:wrap"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="uid" value="{{ u.id }}">
<input name="password" placeholder="yeni şifrə" minlength="8" style="width:140px">
<button name="act" value="reset" class="alt">Şifrəni yenilə</button>
<button name="act" value="delete" class="link" onclick="return confirm('Hesab silinsin?')">Sil</button></form>{% endif %}</td></tr>{% endfor %}</table></div>
{% endblock %}"""

app.jinja_loader = DictLoader(T)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
