import React from 'react';
import './Loader.css';

/**
 * Composant Loader - Animation de chargement pendant le scan
 */

function Loader({ message = 'Scanning in progress...' }) {
    return (
        <div className="loader-overlay">
            <div className="loader-container">
                <div className="loader-spinner"></div>
                <div className="loader-message">{message}</div>
                <div className="loader-subtext">
                    This may take a few moments...
                </div>
            </div>
        </div>
    );
}

export default Loader;
