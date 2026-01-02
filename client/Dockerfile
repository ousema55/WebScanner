# Build stage - Construction de l'application React
FROM node:18-alpine AS build

WORKDIR /app

# Copier les fichiers de dépendances
COPY package*.json ./

# Installer les dépendances
RUN npm install

# Copier les fichiers source
COPY . .

# Build de production
RUN npm run build

# Production stage - Serveur nginx pour servir les fichiers statiques
FROM nginx:alpine

# Copier les fichiers buildés depuis le stage précédent
COPY --from=build /app/build /usr/share/nginx/html

# Copier la configuration nginx personnalisée (optionnel)
# COPY nginx.conf /etc/nginx/conf.d/default.conf

# Exposer le port 80
EXPOSE 3000

# Nginx démarre automatiquement
CMD ["nginx", "-g", "daemon off;"]
