from flask import Flask, request, jsonify, render_template_string
import json
import os
import sys

app = Flask(__name__)
DATA_FILE = "data.json"

# Load existing data or initialize an empty dictionary
if os.path.exists(DATA_FILE):
    with open(DATA_FILE, "r") as f:
        data = json.load(f)
else:
    data = {}


@app.route("/")
def index():
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
                <li><a href="/paste/{{ id }}">{{ id }}</a></li>
            {% endfor %}
        </ul>
    """,
        entries=data,
    )


@app.route("/paste", methods=["POST"])
def paste():
    content = request.form["content"]
    paste_id = str(len(data) + 1)
    data[paste_id] = content
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)
    return jsonify({"id": paste_id, "content": content})


@app.route("/paste/<paste_id>", methods=["GET"])
def get_paste(paste_id):
    content = data.get(paste_id)
    if content:
        return jsonify({"id": paste_id, "content": content})
    else:
        return jsonify({"error": "Paste not found"}), 404


if __name__ == "__main__":
    app.run(debug=True)
