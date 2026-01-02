# Utiliser Python 3.10 slim comme base
FROM python:3.10-slim

# Définir le répertoire de travail
WORKDIR /app

# Copier le fichier requirements.txt
COPY requirements.txt .

# Installer les dépendances Python
RUN pip install --no-cache-dir -r requirements.txt

# Copier tous les fichiers du projet
COPY . .

# Exposer le port 5000 pour Flask
EXPOSE 5000

# Variables d'environnement
ENV FLASK_APP=app.py
ENV FLASK_ENV=development
ENV PYTHONUNBUFFERED=1

# Commande pour démarrer l'application Flask
# --host=0.0.0.0 permet l'accès depuis l'extérieur du container
CMD ["python", "app.py"]
