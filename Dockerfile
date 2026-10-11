FROM node:22-alpine

WORKDIR /app

# Installation des dépendances
COPY package*.json ./
RUN npm install --legacy-peer-deps

# Copie du code source et compilation du frontend React/Vite
COPY . .
RUN npm run build

# Configuration de l'environnement de production
ENV NODE_ENV=production
ENV PORT=3000

EXPOSE 3000

# Vérification de santé du conteneur pour Portainer
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:3000/api/health || exit 1

# Démarrage du serveur Express + API SOC Nebula
CMD ["npm", "start"]
