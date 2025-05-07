from flask import Flask, request, jsonify, render_template_string, redirect
from typing import Optional
import sqlite3
import os


DB_PATH = "./app.db"
app = Flask(__name__)


def get_db():
    return sqlite3.connect(DB_PATH)


@app.route("/")
def index():
    db = get_db()
    data = db.execute("SELECT id FROM pastes").fetchall()
    data = {row[0] for row in data}
    return render_template_string(
        """
        <h1>Pastebin</h1>
        <h2>New paste</h2>
        <form action="/paste" method="post">
            <label style="display:block" for="id">Id</label>
            <input style="display:block; margin-bottom:8px" name="id" placeholder="Custom alphanumeric id" />
            <label style="display:block" for="content">Content</label>
            <textarea style="display:block; margin-bottom:8px" name="content" rows="10" cols="30" placeholder="Content"></textarea>
            <label style="display:block" for="password">Password</label>
            <input style="display:block; margin-bottom:8px" type="password" name="password" placeholder="Password" />
            <input type="hidden" name="redirect" value="/" />
            <input type="submit" value="Create">
        </form>
        <h2>Pastes</h2>
        <ul>
            {% for id in entries %}
                <li>{{ id }} (<a href="/paste/{{ id }}">view</a>)</li>
            {% endfor %}
        </ul>
        """,
        entries=data,
    )


def insert_paste(title: str, content: str, password: str):
    with get_db() as db:
        cursor = db.cursor()
        cursor.execute("INSERT INTO pastes (id, content, password) VALUES (?, ?, ?)", [title, content, password])
        paste_id = cursor.lastrowid
        return paste_id


def get_paste_content(paste_id: str) -> Optional[str]:
    with get_db() as db:
        row = db.execute("SELECT content FROM pastes WHERE id=?", [paste_id]).fetchone()
        if row is None:
            return None
        else:
            return row[0]


def render_error(message: str) -> str:
    return render_template_string("""
    <h1>Error: {{ message }}</h1>
    <a href="/">Home</a>
    """, message=message)


@app.route("/paste", methods=["POST"])
def paste_api():
    if (id := request.form.get("id")) is None:
        return jsonify({"error": "Missing 'title'"}), 400
    if (content := request.form.get("content")) is None:
        return jsonify({"error": "Missing 'content'"}), 400
    if (password := request.form.get("password")) is None:
        return jsonify({"error": "Missing 'password'"}), 400

    if get_paste_content(id) is not None:
        return render_error("Paste ID already taken"), 400

    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
    if type(id) != str and not all(c in allowed for c in id):
        return jsonify({"error": "Id must be alphanumeric ('_' & '-' allowed as well)"}), 400

    try:
        insert_paste(id, content, password)
        return redirect("/")
    except Exception:
        return render_error("Failed to create paste"), 500


@app.route("/paste/<paste_id>", methods=["GET", "POST"])
def get_paste(paste_id):
    if request.method == "GET":
        content = get_paste_content(paste_id)

        if content is None:
            return render_error("Paste not found"), 404
        else:
            return f"""
            <h1>This paste is password protected</h1>
            <form action="/paste/{paste_id}" method="POST">
                <input type="password" name="password" placeholder="Password" />
                <input type="submit" value="Submit">
            </form>
            <a href="/">Home</a>
            """
    else:
        if (password := request.form["password"]) is None:
            return jsonify({"error": "Missing password"}), 400

        with get_db() as db:
            row = db.execute("SELECT content FROM pastes WHERE id='%s' AND password='%s'" % (paste_id, password)).fetchone()

        if row is None:
            return render_error("Incorrect password"), 403
        else:
            return render_template_string("""
            <h1>Paste '{{ id }}'</h1>
            <h2>Content</h2>
            <pre>{{ content }}</pre>
            <a style="display:block; margin-top:30px" href="/">Home</a>
            """, id=paste_id, content=row[0])


@app.route("/health")
def health():
    return "OK"


if __name__ == "__main__":
    with get_db() as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS pastes (
                id TEXT PRIMARY KEY,
                content TEXT,
                password TEXT
            )
            """
        )
    db.close()

    app.run(debug=True, host="0.0.0.0", port=os.getenv("PORT", 5000))
