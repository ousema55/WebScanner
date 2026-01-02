import React, { useState } from 'react';
import Scanner from './components/Scanner';
import Results from './components/Results';
import Loader from './components/Loader';
import { scannerAPI } from './services/api';
import './App.css';

function App() {
    const [results, setResults] = useState(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);

    const handleScan = async (url, options = {}) => {
        setLoading(true);
        setError(null);

        try {
            console.log(`Starting scan for: ${url}`);

            // Appel à l'API avec Axios
            const data = await scannerAPI.scan(url, options);

            console.log('Scan completed:', data);
            setResults(data);

        } catch (error) {
            console.error("Scan failed:", error);

            // Gestion d'erreurs améliorée
            let errorMessage = 'Scan failed. ';

            if (error.response) {
                // Le serveur a répondu avec une erreur
                errorMessage += error.response.data?.error || error.response.statusText;
            } else if (error.request) {
                // Pas de réponse du serveur
                errorMessage += 'No response from server. Is the backend running on port 5000?';
            } else {
                // Erreur de configuration
                errorMessage += error.message;
            }

            setError(errorMessage);
            setResults({ success: false, error: errorMessage });

        } finally {
            setLoading(false);
        }
    };

    const handleReset = () => {
        setResults(null);
        setError(null);
    };

    return (
        <div className="App">
            <header className="App-header">
                <h1>WebSec Scanner</h1>
            </header>
            <main>
                {loading && <Loader message="Scanning for vulnerabilities" />}

                {!results ? (
                    <Scanner onScan={handleScan} loading={loading} />
                ) : (
                    <Results results={results} onBack={handleReset} />
                )}
            </main>
        </div>
    );
}

export default App;
