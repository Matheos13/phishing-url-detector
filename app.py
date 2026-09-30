import sys
from pathlib import Path
from flask import Flask, render_template, request

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
from predict import check_url

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if url:
            result = check_url(url)
    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)