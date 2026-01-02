import React, { useState } from 'react';

function Scanner({ onScan, loading }) {
    const [url, setUrl] = useState('');

    const handleSubmit = (e) => {
        e.preventDefault();
        if (url) {
            onScan(url);
        }
    };

    return (
        <div className="container">
            <header>
                <div className="logo">
                    <i className="fas fa-shield-alt"></i> WebSec Scanner
                </div>
                <p className="subtitle">Advanced XSS & SQLi Vulnerability Analyzer</p>
            </header>

            <main>
                <div className="card scan-card">
                    <h2>Start New Scan</h2>
                    <p>Enter the target URL to detect potential security vulnerabilities.</p>

                    <form onSubmit={handleSubmit}>
                        <div className="input-group">
                            <i className="fas fa-globe"></i>
                            <input
                                type="url"
                                name="url"
                                value={url}
                                onChange={(e) => setUrl(e.target.value)}
                                placeholder="http://example.com"
                                required
                                disabled={loading}
                            />
                        </div>

                        <button type="submit" className="btn-scan" disabled={loading}>
                            <span className="btn-text">
                                {loading ? 'Scanning...' : 'Start Scan'}
                            </span>
                        </button>
                    </form>
                </div>

                <div className="features">
                    <div className="feature-item">
                        <i className="fas fa-code"></i>
                        <h3>XSS Detection</h3>
                        <p>Tests for Reflected, Stored, and DOM-based XSS.</p>
                    </div>
                    <div className="feature-item">
                        <i className="fas fa-database"></i>
                        <h3>SQL Injection</h3>
                        <p>Checks for Error-based and Boolean-based SQLi.</p>
                    </div>
                    <div className="feature-item">
                        <i className="fas fa-file-alt"></i>
                        <h3>Detailed Reports</h3>
                        <p>Get comprehensive logs and vulnerability details.</p>
                    </div>
                </div>
            </main>
        </div>
    );
}

export default Scanner;