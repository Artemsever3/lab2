#!/usr/bin/env python3
"""
Лабораторная работа №2 — Часть 1
Учебное веб-приложение на Flask, намеренно содержащее уязвимости
из OWASP Top 10 (2021):

  1. A03:2021 - Injection            -> SQL Injection в /login
  2. A03:2021 - Injection            -> Stored XSS в /comments
  3. A01:2021 - Broken Access Control -> IDOR в /profile/<user_id>

ВНИМАНИЕ: приложение создано ИСКЛЮЧИТЕЛЬНО в учебных целях.
Запускать только локально / в изолированной виртуальной машине,
не публиковать в интернете и не использовать в продакшене.
"""

import sqlite3
import os
from flask import Flask, request, session, redirect, url_for, make_response

APP_DB = os.path.join(os.path.dirname(__file__), "lab2.db")

app = Flask(__name__)
app.secret_key = "dev-secret-key-not-for-production"  # для сессий в лабораторной работе


# ---------------------------------------------------------------------------
# Инициализация базы данных
# ---------------------------------------------------------------------------
def init_db():
    conn = sqlite3.connect(APP_DB)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            content TEXT NOT NULL
        )
    """)
    # тестовые данные
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        cur.executemany(
            "INSERT INTO users (username, password, email, is_admin) VALUES (?, ?, ?, ?)",
            [
                ("admin", "SuperSecretAdminPass!23", "admin@lab2.local", 1),
                ("alice", "alicepass123", "alice@lab2.local", 0),
                ("bob", "bobpass456", "bob@lab2.local", 0),
            ],
        )
    conn.commit()
    conn.close()


def get_conn():
    conn = sqlite3.connect(APP_DB)
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# Общий layout (безопасен — используется только для статичных частей страницы)
# ---------------------------------------------------------------------------
def layout(body: str) -> str:
    return f"""<!doctype html>
<html lang="ru">
<head><meta charset="utf-8"><title>Lab2 Vulnerable App</title></head>
<body style="font-family:sans-serif;max-width:700px;margin:40px auto">
<h1>Учебное веб-приложение (Lab2)</h1>
<p><a href="/">Главная</a> | <a href="/comments">Комментарии</a> |
<a href="/login">Вход</a> | <a href="/register">Регистрация</a> | <a href="/logout">Выход</a></p>
<hr>
{body}
</body></html>"""


# ---------------------------------------------------------------------------
# Главная страница
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    user = session.get("username")
    uid = session.get("user_id")
    if user:
        body = f"""
        <p>Вы вошли как <b>{user}</b> (id={uid}).</p>
        <p><a href="/profile/{uid}">Мой профиль</a></p>
        """
    else:
        body = "<p>Вы не авторизованы. <a href='/login'>Войти</a></p>"
    return layout(body)


# ---------------------------------------------------------------------------
# УЯЗВИМОСТЬ №1: SQL Injection (A03:2021 - Injection)
# Параметры подставляются в SQL-запрос прямой конкатенацией строк.
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        conn = get_conn()
        cur = conn.cursor()

        # !!! УЯЗВИМЫЙ КОД: небезопасная конкатенация строк в SQL-запросе !!!
        query = ("SELECT id, username, is_admin FROM users "
                  "WHERE username = '%s' AND password = '%s'") % (username, password)
        try:
            cur.execute(query)
            row = cur.fetchone()
        except sqlite3.Error as e:
            row = None
            error = f"Ошибка SQL: {e}"
        conn.close()

        if row:
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            session["is_admin"] = bool(row["is_admin"])
            return redirect(url_for("index"))
        else:
            error = error or "Неверный логин или пароль"

    body = f"""
    <h2>Вход</h2>
    {"<p style='color:red'>" + error + "</p>" if error else ""}
    <form method="post">
      Логин: <input name="username"><br><br>
      Пароль: <input name="password" type="password"><br><br>
      <button type="submit">Войти</button>
    </form>
    """
    return layout(body)


@app.route("/register", methods=["GET", "POST"])
def register():
    msg = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        if username and password:
            conn = get_conn()
            cur = conn.cursor()
            try:
                # здесь используется безопасный параметризованный запрос
                cur.execute(
                    "INSERT INTO users (username, password, email, is_admin) VALUES (?, ?, ?, 0)",
                    (username, password, email),
                )
                conn.commit()
                msg = "Пользователь создан, можно войти."
            except sqlite3.IntegrityError:
                msg = "Такой пользователь уже существует."
            conn.close()

    body = f"""
    <h2>Регистрация</h2>
    {"<p>" + msg + "</p>" if msg else ""}
    <form method="post">
      Логин: <input name="username"><br><br>
      Пароль: <input name="password" type="password"><br><br>
      Email: <input name="email"><br><br>
      <button type="submit">Зарегистрироваться</button>
    </form>
    """
    return layout(body)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# УЯЗВИМОСТЬ №2: Stored XSS (A03:2021 - Injection)
# Содержимое комментария выводится в HTML без экранирования.
# ---------------------------------------------------------------------------
@app.route("/comments", methods=["GET", "POST"])
def comments():
    if request.method == "POST":
        if not session.get("username"):
            return redirect(url_for("login"))
        content = request.form.get("content", "")
        conn = get_conn()
        cur = conn.cursor()
        # Сохранение — параметризовано и безопасно само по себе
        cur.execute(
            "INSERT INTO comments (username, content) VALUES (?, ?)",
            (session["username"], content),
        )
        conn.commit()
        conn.close()
        return redirect(url_for("comments"))

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT username, content FROM comments ORDER BY id DESC")
    rows = cur.fetchall()
    conn.close()

    items_html = ""
    for r in rows:
        # !!! УЯЗВИМЫЙ КОД: content вставляется в HTML без экранирования !!!
        items_html += f"<div style='border:1px solid #ccc;padding:8px;margin:6px 0'>" \
                       f"<b>{r['username']}</b>: {r['content']}</div>"

    form_html = ""
    if session.get("username"):
        form_html = """
        <form method="post">
          <textarea name="content" rows="3" cols="50" placeholder="Ваш комментарий"></textarea><br>
          <button type="submit">Отправить</button>
        </form>
        """
    else:
        form_html = "<p>Войдите, чтобы оставить комментарий.</p>"

    body = f"<h2>Комментарии</h2>{form_html}<hr>{items_html}"
    return layout(body)


# ---------------------------------------------------------------------------
# УЯЗВИМОСТЬ №3: IDOR / Broken Access Control (A01:2021)
# Любой авторизованный пользователь может запросить профиль ЛЮБОГО
# пользователя по id, без проверки владения ресурсом.
# ---------------------------------------------------------------------------
@app.route("/profile/<int:user_id>")
def profile(user_id):
    if not session.get("username"):
        return redirect(url_for("login"))

    conn = get_conn()
    cur = conn.cursor()
    # !!! УЯЗВИМЫЙ КОД: нет проверки, что user_id принадлежит текущей сессии !!!
    cur.execute("SELECT id, username, email, password, is_admin FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return layout("<p>Пользователь не найден.</p>"), 404

    body = f"""
    <h2>Профиль пользователя</h2>
    <ul>
      <li>ID: {row['id']}</li>
      <li>Логин: {row['username']}</li>
      <li>Email: {row['email']}</li>
      <li>Пароль (демонстрация утечки данных): {row['password']}</li>
      <li>Администратор: {'да' if row['is_admin'] else 'нет'}</li>
    </ul>
    """
    return layout(body)


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)
