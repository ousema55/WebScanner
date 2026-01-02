/**
 * API Service - Axios Client
 * 
 * Service centralisé pour communiquer avec le backend Flask
 */

import axios from 'axios';

// URL de base de l'API backend
const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';

// Créer une instance Axios avec configuration par défaut
const apiClient = axios.create({
    baseURL: API_BASE_URL,
    timeout: 300000, // 5 minutes (les scans peuvent être longs)
    headers: {
        'Content-Type': 'application/json',
    },
});

// Intercepteur de requêtes (pour ajouter des headers, tokens, etc.)
apiClient.interceptors.request.use(
    (config) => {
        // On peut ajouter des tokens d'authentification ici si nécessaire
        // config.headers.Authorization = `Bearer ${token}`;
        console.log(`[API Request] ${config.method.toUpperCase()} ${config.url}`);
        return config;
    },
    (error) => {
        console.error('[API Request Error]', error);
        return Promise.reject(error);
    }
);

// Intercepteur de réponses (pour gérer les erreurs globalement)
apiClient.interceptors.response.use(
    (response) => {
        console.log(`[API Response] ${response.status} ${response.config.url}`);
        return response;
    },
    (error) => {
        console.error('[API Response Error]', error.response || error.message);

        // Gestion d'erreurs personnalisée
        if (error.response) {
            // Le serveur a répondu avec un code d'erreur
            const { status, data } = error.response;

            switch (status) {
                case 400:
                    console.error('Bad Request:', data.error);
                    break;
                case 404:
                    console.error('Not Found:', data.error);
                    break;
                case 500:
                    console.error('Server Error:', data.error);
                    break;
                default:
                    console.error('Error:', data.error || 'Unknown error');
            }
        } else if (error.request) {
            // La requête a été faite mais pas de réponse
            console.error('No response from server. Is the backend running?');
        } else {
            // Erreur lors de la configuration de la requête
            console.error('Request setup error:', error.message);
        }

        return Promise.reject(error);
    }
);

/**
 * Scanner API
 */
export const scannerAPI = {
    /**
     * Lance un scan de vulnérabilités
     * @param {string} url - URL cible à scanner
     * @param {object} options - Options supplémentaires (login, credentials, max_pages)
     * @returns {Promise} Résultats du scan
     */
    scan: async (url, options = {}) => {
        try {
            const response = await apiClient.post('/api/scan', {
                url,
                ...options
            });
            return response.data;
        } catch (error) {
            throw error;
        }
    },

    /**
     * Vérifie la santé de l'API
     * @returns {Promise} Status de l'API
     */
    healthCheck: async () => {
        try {
            const response = await apiClient.get('/api/health');
            return response.data;
        } catch (error) {
            throw error;
        }
    },

    /**
     * Récupère les informations de l'API
     * @returns {Promise} Informations de l'API
     */
    getInfo: async () => {
        try {
            const response = await apiClient.get('/');
            return response.data;
        } catch (error) {
            throw error;
        }
    }
};

/**
 * Export par défaut de l'instance Axios configurée
 */
export default apiClient;
