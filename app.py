from flask import Flask, request, render_template
from scanner import scan_multiple

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        raw_urls = request.form.get("urls", "")
        url_list = [u.strip() for u in raw_urls.splitlines() if u.strip()]
        if not url_list:
            return render_template("index.html", error="Please enter at least one URL.")
        results = scan_multiple(url_list)
        return render_template("results.html", results=results)
    return render_template("index.html")


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5050))
    app.run(host="0.0.0.0", port=port, debug=False)
