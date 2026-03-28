from flask import Flask, request, jsonify
import subprocess
import json

app = Flask(__name__)

@app.route("/analyze", methods=["POST"])
def analyze():
    url = request.json.get("url")

    result = subprocess.run(
        ["python", "test.py", url],
        capture_output=True,
        text=True
    )

    data = json.loads(result.stdout)
    return jsonify(data)

app.run(port=5000)