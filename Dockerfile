FROM node:22-bookworm-slim

WORKDIR /app

# Configuration mémoire et environnement pour installer toutes les dépendances de compilation (Vite / Tailwind Oxide / LightningCSS)
ENV NODE_ENV=development
ENV NODE_OPTIONS="--max-old-space-size=4096"

# Installation des dépendances avec les binaires natifs Linux GNU (glibc / libgcc_s)
COPY package.json ./
RUN npm install --legacy-peer-deps --include=dev --include=optional

# Copie du code source (et du dossier dist/ pré-compilé en secours)
COPY . .

# Compilation du frontend React/Vite (avec bascule automatique sur dist/ si l'architecture CPU hôte limite les binaires natifs)
RUN npm run build || (echo "Utilisation du build de production pré-compilé dist/..." && test -f dist/index.html)

# Configuration de l'environnement d'exécution de production
ENV NODE_ENV=production
ENV PORT=3000

EXPOSE 3000

# Vérification de santé du conteneur pour Portainer via Node.js natif (sans dépendre de wget/curl)
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/api/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

# Démarrage du serveur Express + API SOC Nebula
CMD ["npm", "start"]
