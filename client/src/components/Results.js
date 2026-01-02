import React from 'react';

/**
 * Composant Results - Affichage des résultats du scan
 * 
 * Affiche les statistiques, formulaires détectés, vulnérabilités XSS/SQLi,
 * et les logs techniques du scan de sécurité.
 */

function Results({ results, onBack }) {
    if (!results || !results.success) {
        return (
            <div className="container">
                <div className="card">
                    <div style={{ textAlign: 'center', padding: '3rem' }}>
                        <i className="fas fa-exclamation-triangle" style={{ fontSize: '4rem', color: '#e74c3c', marginBottom: '1rem' }}></i>
                        <h2 style={{ color: '#e74c3c' }}>Erreur de Scan</h2>
                        <p style={{ color: '#b8c5d6', marginBottom: '2rem' }}>
                            {results?.error || 'Une erreur est survenue lors du scan.'}
                        </p>
                        <button onClick={onBack} className="btn-scan">
                            <i className="fas fa-arrow-left"></i> Retour
                        </button>
                    </div>
                </div>
            </div>
        );
    }

    const data = results.results;
    const xssVulns = data.vulnerabilities.filter(v => v.type === 'XSS');
    const sqliVulns = data.vulnerabilities.filter(v => v.type !== 'XSS');

    return (
        <div className="container">
            {/* En-tête des résultats */}
            <div className="card results-card">
                <div className="results-header">
                    <h1><i className="fas fa-chart-bar"></i> Rapport de Scan</h1>
                    <div className="target-url">
                        <strong>URL Cible :</strong> {data.target_url}
                    </div>
                </div>

                {/* Statistiques */}
                <div className="stats-grid">
                    <div className="stat-card">
                        <div className="stat-number">{data.pages_crawled}</div>
                        <div className="stat-label">Pages Crawlées</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-number">{data.forms_found.length}</div>
                        <div className="stat-label">Formulaires Trouvés</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-number" style={{ color: data.vulnerabilities.length > 0 ? '#e74c3c' : '#2ecc71' }}>
                            {data.vulnerabilities.length}
                        </div>
                        <div className="stat-label">Vulnérabilités Détectées</div>
                    </div>
                </div>

                {/* Formulaires Détectés */}
                <section className="results-section">
                    <h2 className="section-title">
                        <i className="fas fa-list"></i> Formulaires Détectés
                    </h2>

                    {data.forms_found.length > 0 ? (
                        <div className="table-container">
                            <table>
                                <thead>
                                    <tr>
                                        <th>URL</th>
                                        <th>Action</th>
                                        <th>Méthode</th>
                                        <th>Paramètres</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {data.forms_found.map((form, index) => (
                                        <tr key={index}>
                                            <td>{form.url}</td>
                                            <td>{form.action || '(page actuelle)'}</td>
                                            <td>
                                                <span className={`badge badge-${form.method}`}>
                                                    {form.method.toUpperCase()}
                                                </span>
                                            </td>
                                            <td>
                                                {form.inputs.map((input, idx) => (
                                                    <span key={idx} className="badge badge-param">
                                                        {input.name} ({input.type})
                                                    </span>
                                                ))}
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    ) : (
                        <div className="empty-state">
                            <i className="fas fa-inbox"></i>
                            <p>Aucun formulaire détecté sur le site cible.</p>
                        </div>
                    )}
                </section>

                {/* Vulnérabilités XSS */}
                <section className="results-section">
                    <h2 className="section-title">
                        <i className="fas fa-code"></i> Vulnérabilités XSS
                    </h2>

                    {xssVulns.length > 0 ? (
                        <div className="table-container">
                            <table>
                                <thead>
                                    <tr>
                                        <th>URL</th>
                                        <th>Méthode</th>
                                        <th>Payload</th>
                                        <th>Sévérité</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {xssVulns.map((vuln, index) => (
                                        <tr key={index}>
                                            <td>{vuln.url}</td>
                                            <td>
                                                <span className={`badge badge-${vuln.method}`}>
                                                    {vuln.method.toUpperCase()}
                                                </span>
                                            </td>
                                            <td><code className="vuln-payload">{vuln.payload}</code></td>
                                            <td>
                                                <span className={`badge badge-${vuln.severity.toLowerCase()}`}>
                                                    {vuln.severity}
                                                </span>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    ) : (
                        <div className="empty-state">
                            <i className="fas fa-shield-alt"></i>
                            <p style={{ color: '#2ecc71' }}>✓ Aucune vulnérabilité XSS détectée.</p>
                        </div>
                    )}
                </section>

                {/* Vulnérabilités SQLi */}
                <section className="results-section">
                    <h2 className="section-title">
                        <i className="fas fa-database"></i> Vulnérabilités SQL Injection
                    </h2>

                    {sqliVulns.length > 0 ? (
                        <div className="table-container">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Type</th>
                                        <th>URL</th>
                                        <th>Méthode</th>
                                        <th>Payload</th>
                                        <th>Détails</th>
                                        <th>Sévérité</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {sqliVulns.map((vuln, index) => (
                                        <tr key={index}>
                                            <td>{vuln.type}</td>
                                            <td>{vuln.url}</td>
                                            <td>
                                                <span className={`badge badge-${vuln.method}`}>
                                                    {vuln.method.toUpperCase()}
                                                </span>
                                            </td>
                                            <td><code className="vuln-payload">{vuln.payload}</code></td>
                                            <td>{vuln.description}</td>
                                            <td>
                                                <span className="badge badge-critical">
                                                    {vuln.severity}
                                                </span>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    ) : (
                        <div className="empty-state">
                            <i className="fas fa-shield-alt"></i>
                            <p style={{ color: '#2ecc71' }}>✓ Aucune vulnérabilité SQL Injection détectée.</p>
                        </div>
                    )}
                </section>

                {/* Logs Techniques */}
                <section className="results-section">
                    <h2 className="section-title">
                        <i className="fas fa-terminal"></i> Logs Techniques
                    </h2>

                    <div className="logs-container">
                        <div className="log-entry log-success">[✓] Scan initié sur {data.target_url}</div>
                        <div className="log-entry">[@] Pages crawlées: {data.pages_crawled}</div>
                        {data.crawled_urls.map((url, index) => (
                            <div key={index} className="log-entry">  → {url}</div>
                        ))}

                        <div className="log-entry">[@] Formulaires analysés: {data.forms_found.length}</div>

                        {data.vulnerabilities.length > 0 ? (
                            <>
                                <div className="log-entry log-warning">
                                    [!] Vulnérabilités détectées: {data.vulnerabilities.length}
                                </div>
                                {data.vulnerabilities.map((vuln, index) => (
                                    <div key={index} className="log-entry log-error">
                                        [!] {vuln.type} → {vuln.url}
                                    </div>
                                ))}
                            </>
                        ) : (
                            <div className="log-entry log-success">[✓] Aucune vulnérabilité détectée</div>
                        )}

                        <div className="log-entry log-success">[✓] Scan terminé avec succès</div>
                    </div>
                </section>

                {/* Bouton Retour */}
                <div style={{ textAlign: 'center', marginTop: '2rem' }}>
                    <button onClick={onBack} className="btn-scan">
                        <i className="fas fa-arrow-left"></i> Nouvelle Analyse
                    </button>
                </div>
            </div>
        </div>
    );
}

export default Results;
