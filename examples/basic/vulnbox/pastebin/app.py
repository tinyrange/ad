from flask import Flask, request, jsonify, render_template_string, redirect
import sqlite3
import os


DB_PATH = "./app.db"
app = Flask(__name__)


def get_db():
    return sqlite3.connect(DB_PATH)


@app.route("/")
def index():
    db = get_db()
    data = db.execute("SELECT id, content FROM pastes").fetchall()
    data = {row[0]: row[1] for row in data}
    return render_template_string(
        """
        <h1>Pastebin</h1>
        <form action="/paste" method="post">
            <textarea name="content" rows="10" cols="30"></textarea><br>
            <input type="submit" value="Submit">
        </form>
        <h2>Pastes</h2>
        <ul>
            {% for id, content in entries.items() %}
                <li>
                    <a href="/paste/{{ id }}">{{ id }}</a>
                    <pre>{{ content }}</pre>
                </li>
            {% endfor %}
        </ul>
        """,
        entries=data,
    )


def insert_paste(content: str):
    with get_db() as db:
        cursor = db.cursor()
        cursor.execute("INSERT INTO pastes (content) VALUES (?)", [content])
        paste_id = cursor.lastrowid
        return paste_id


@app.route("/paste", methods=["POST"])
def paste():
    content = request.form["content"]
    insert_paste(content)
    return redirect("/")


@app.route("/api/paste", methods=["POST"])
def paste_api():
    content = request.form["content"]
    paste_id = insert_paste(content)
    return jsonify({"id": paste_id, "content": content})


@app.route("/api/paste/<paste_id>", methods=["GET"])
def get_paste(paste_id):
    with get_db() as db:
        row = db.execute("SELECT content FROM pastes WHERE id=?", [paste_id]).fetchone()

    if row is not None:
        return jsonify({"id": paste_id, "content": row[0]})
    else:
        return jsonify({"error": "Paste not found"}), 404


@app.route("/health")
def health():
    return "OK"


if __name__ == "__main__":
    with get_db() as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS pastes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content TEXT
            )
            """
        )
    db.close()

    app.run(debug=True, host="0.0.0.0", port=os.getenv("PORT", 5000))
