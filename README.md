# NebulaGuard AI SOC — Zyxel Nebula & SecuReporter

Plateforme SOC d'analyse de menaces, surveillance continue multi-organisations/multi-sites et riposte pare-feu pour passerelles **Zyxel Nebula Cloud (ATP Series, USG FLEX & SecuReporter)**.

---

## Déploiement dans Portainer (Stacks)

### Méthode 1 : Déploiement direct depuis GitHub dans Portainer (Recommandé)

1. Ouvrez **Portainer** et allez dans **Stacks** -> **+ Add stack**.
2. Donnez un nom à votre stack (ex: `nebulaguard-zyxel-soc`).
3. Dans **Build method**, sélectionnez **Repository**.
4. Renseignez les paramètres Git :
   - **Repository URL** : `https://github.com/Miguel1978/SecuReporter-Zyxel-Nebula-`
   - **Repository reference** : `refs/heads/main`
   - **Compose path** : `docker-compose.yaml` (ou `docker-compose.yml`)
   - *Si le dépôt est privé* : activez **Authentication** et renseignez votre nom d'utilisateur GitHub et un **Personal Access Token (PAT)**.
5. Dans la section **Environment variables** de Portainer, ajoutez vos variables (optionnelles ou personnalisées) :
   - `HOST_PORT` = `3000` (ou un autre port disponible sur votre serveur, ex: `8085`)
   - `GEMINI_API_KEY` = `votre_cle_api_gemini` *(optionnel : un moteur d'analyse SOC algorithmique local prend automatiquement le relais si vide ou hors quota)*
   - `ZYXEL_NEBULA_ORG_ID` = `ORG-ZYXEL-FR-88412`
   - `ZYXEL_NEBULA_SITE_ID` = `site-paris-hq`
   - `ZYXEL_NEBULA_API_URL` = `https://api.nebula.zyxel.com/v1`
   - `ZYXEL_NEBULA_API_KEY` = `votre_cle_nebula`
6. Cliquez sur **Deploy the stack**.
7. Accédez à l'application sur `http://<IP_DE_VOTRE_SERVEUR>:3000`.

---

### Méthode 2 : En ligne de commande (Docker Compose)

```bash
git clone https://github.com/Miguel1978/SecuReporter-Zyxel-Nebula-.git
cd SecuReporter-Zyxel-Nebula-
docker compose -f docker-compose.yaml up -d --build
```

---

## Vérification de santé (Healthcheck)

Le conteneur expose un point de terminaison de santé utilisé par Docker et Portainer :
- `GET http://localhost:3000/api/health`
