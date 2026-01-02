"""
Web Vulnerability Scanner - Application Flask Simple
====================================================
Routes simples et claires pour tester les sites web
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_cors import CORS
from scanner import Scanner
import threading
import uuid

app = Flask(__name__)
CORS(app)

# Global storage for active scan (single user mode)
CURRENT_SCAN = {
    "scanner": None,
    "thread": None
}

@app.route('/')
def index():
    """Page d'accueil avec formulaire"""
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
    target_url = request.form.get('url')
    cookie = request.form.get('cookie')

    if not target_url:
        return render_template('index.html', error="Please enter a URL")

    # Stop existing scan if any
    if CURRENT_SCAN["scanner"]:
        CURRENT_SCAN["scanner"].stop()
        if CURRENT_SCAN["thread"] and CURRENT_SCAN["thread"].is_alive():
            CURRENT_SCAN["thread"].join(timeout=2)

    scanner = Scanner(target_url, cookie=cookie)
    
    def run_scan_async():
        scanner.run_scan()
        
    thread = threading.Thread(target=run_scan_async)
    thread.daemon = True
    thread.start()
    
    CURRENT_SCAN["scanner"] = scanner
    CURRENT_SCAN["thread"] = thread
    
    # Return results page immediately. The page will poll /api/status
    return render_template('result.html')


@app.route('/api/status', methods=['GET'])
def get_status():
    if not CURRENT_SCAN["scanner"]:
        return jsonify({"error": "No scan running", "logs": [], "vulnerabilities": []})
    
    results = CURRENT_SCAN["scanner"].get_results()
    
    is_finished = not CURRENT_SCAN["thread"].is_alive()
    results["finished"] = is_finished
    
    return jsonify(results)


@app.route('/api/stop', methods=['POST'])
def stop_scan():
    if CURRENT_SCAN["scanner"]:
        CURRENT_SCAN["scanner"].stop()
        return jsonify({"status": "stopping"})
    return jsonify({"status": "no_scan"})


# Legacy API Route (kept for compatibility if needed, but synchronous)
@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.get_json()
    target_url = data.get('url')
    cookie = data.get('cookie')

    if not target_url:
        return jsonify({"error": "URL is required"}), 400

    scanner = Scanner(target_url, cookie=cookie)
    results = scanner.run_scan()
    return jsonify(results)


if __name__ == '__main__':
    print("\n" + "="*60)
    print("    Web Vulnerability Scanner")
    print("="*60)
    print("    http://localhost:5000\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
