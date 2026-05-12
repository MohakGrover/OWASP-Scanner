"""Intentionally vulnerable local demo app for CA presentations only."""

from __future__ import annotations

from flask import Flask, jsonify, make_response, redirect, request

app = Flask(__name__)

USERS = {"admin": "admin", "test": "test"}
ORDERS = {"1": {"owner": "alice", "item": "Laptop"}, "2": {"owner": "bob", "item": "Phone"}}


@app.route("/")
def index():
    return """
    <html><head><title>Demo Shop</title>
    <script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"></script>
    </head>
    <body>
      <h1>Demo E-Commerce</h1>
      <a href="/search">Search</a>
      <a href="/admin">Admin</a>
      <a href="/login">Login</a>
      <a href="/checkout">Checkout</a>
    </body></html>
    """


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        if USERS.get(u) == p:
            resp = make_response(redirect("/dashboard"))
            resp.set_cookie("session", f"{u}-insecure-token")
            return resp
        return "Invalid credentials", 200
    return """
    <form method="post">
      <input name="username"/>
      <input name="password" type="password"/>
      <button>Login</button>
    </form>
    """


@app.route("/search")
def search():
    q = request.args.get("q", "")
    if "'" in q or " or " in q.lower():
        return "mysql_fetch_array() warning: syntax error near unclosed quotation", 200
    return f"Showing results for {q}"


@app.route("/admin")
def admin():
    return "Admin panel (intentionally no auth in demo)", 200


@app.route("/dashboard")
def dashboard():
    return "Dashboard content", 200


@app.route("/api/orders/<order_id>")
def order(order_id):
    return jsonify(ORDERS.get(order_id, {"error": "not found"}))


@app.route("/download")
def download():
    file = request.args.get("file", "")
    if "etc/passwd" in file:
        return "root:x:0:0:root:/root:/bin/bash"
    if "win.ini" in file.lower():
        return "[extensions]"
    return "file not found", 404


@app.route("/import")
def import_url():
    url = request.args.get("url", "")
    return f"connection refused while fetching {url}", 200


@app.route("/.env")
def env_file():
    return "DB_PASSWORD=demo-secret\nAPI_KEY=demo-key", 200


@app.route("/uploads/")
def uploads():
    return "<title>Directory listing</title><h1>Index of /uploads</h1>", 200


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
