# Plan d'implémentation: Mot de passe oublié

## Vue d'ensemble du projet
Implémentation complète de la fonctionnalité "mot de passe oublié" dans l'architecture existante Cloudflare Workers + D1 + React, avec support bilingue français/anglais.

## ✅ STATUT: IMPLÉMENTATION TERMINÉE

L'implémentation complète du système de récupération de mot de passe est terminée. Toutes les fonctionnalités sont opérationnelles.

## Architecture existante analysée
- **Backend**: Cloudflare Workers avec D1 database
- **Frontend**: React 19 avec authentification via JWT
- **API Service**: `apiService.js` avec gestion des tokens
- **Auth Context**: `AuthContext.js` avec méthodes login/register/logout
- **Traductions**: Système bilingue déjà en place dans `constants.js`

## Flow complet mot de passe oublié

### 1. Demande de réinitialisation
1. Utilisateur saisit son email sur page "Mot de passe oublié"
2. Frontend envoie POST `/api/auth/forgot-password` avec email
3. Backend vérifie si email existe en base
4. Génère un token sécurisé (UUID + timestamp)
5. Sauvegarde token en D1 avec expiration (15 minutes)
6. Envoie email avec lien de réinitialisation
7. Retourne succès (même si email n'existe pas - sécurité)

### 2. Réinitialisation du mot de passe
1. Utilisateur clique sur lien email -> redirigé vers `/reset-password?token=xxx`
2. Frontend affiche formulaire nouveau mot de passe
3. Utilisateur saisit nouveau mot de passe + confirmation
4. Frontend envoie POST `/api/auth/reset-password` avec token + nouveau mot de passe
5. Backend valide token (existence + expiration)
6. Hash nouveau mot de passe et update en base
7. Supprime token de réinitialisation
8. Retourne succès + auto-login de l'utilisateur

## Implémentation technique détaillée

### Backend - Endpoints Cloudflare Workers

#### 1. POST /api/auth/forgot-password
```javascript
// Dans le worker principal
{
  method: 'POST',
  body: { email: string },
  response: { success: boolean, message: string }
}
```

**Logique:**
- Valider format email
- Vérifier existence utilisateur en D1
- Générer token sécurisé: `crypto.randomUUID() + timestamp`
- Sauvegarder en table `password_reset_tokens` avec expiration 15min
- Envoyer email via service Cloudflare (Mailgun/SendGrid)
- Toujours retourner succès (pas d'énumération d'emails)

#### 2. POST /api/auth/reset-password
```javascript
{
  method: 'POST', 
  body: { token: string, password: string },
  response: { success: boolean, message: string, token?: string, user?: object }
}
```

**Logique:**
- Valider token format
- Chercher token en D1 avec jointure user
- Vérifier expiration (created_at + 15min > maintenant)
- Valider force mot de passe (min 8 chars, etc.)
- Hasher nouveau mot de passe avec bcrypt
- Transaction D1: update password + delete reset token
- Générer nouveau JWT pour auto-login
- Retourner token + user data

### Base de données D1

#### Table: password_reset_tokens
```sql
CREATE TABLE password_reset_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  token TEXT NOT NULL UNIQUE,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME NOT NULL,
  used BOOLEAN DEFAULT FALSE,
  FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX idx_reset_token ON password_reset_tokens(token);
CREATE INDEX idx_reset_expires ON password_reset_tokens(expires_at);
```

### Frontend - Composants React

#### 1. Composant ForgotPassword
**Localisation**: `auth/ForgotPassword.js`
**Features**:
- Formulaire email avec validation
- Intégration apiService pour appel backend
- Gestion états loading/success/error
- Traductions FR/EN via useLanguage
- Lien retour vers login

#### 2. Composant ResetPassword  
**Localisation**: `auth/ResetPassword.js`
**Features**:
- Extraction token depuis URL params
- Formulaire mot de passe + confirmation
- Validation côté client (longueur, matching)
- Appel backend + gestion auto-login
- Redirect vers dashboard après succès

#### 3. Intégration dans AuthContext
Ajout méthodes:
```javascript
const forgotPassword = async (email) => { /* */ }
const resetPassword = async (token, password) => { /* */ }
```

#### 4. Routes et navigation
- Modifier composant Login: ajouter lien "Mot de passe oublié"
- Router: ajouter routes `/forgot-password` et `/reset-password`
- Redirection automatique après reset réussi

### Service email Resend

#### Configuration
- Utiliser Resend API via Cloudflare Workers
- Variables d'environnement: `RESEND_API_KEY`, domaine vérifié
- Template email HTML avec React Email ou HTML simple
- Endpoint: `https://api.resend.com/emails`

#### Intégration Cloudflare Workers
```javascript
// Dans le worker
const sendResetEmail = async (email, token, language = 'fr') => {
  const resetUrl = `${FRONTEND_URL}/reset-password?token=${token}&lang=${language}`;
  
  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: 'TeachInspire <noreply@votredomaine.com>',
      to: [email],
      subject: language === 'fr' 
        ? 'Réinitialisation de votre mot de passe - TeachInspire'
        : 'Reset your password - TeachInspire',
      html: getEmailTemplate(resetUrl, language)
    }),
  });

  return response.ok;
};
```

#### Template email
- Sujet: "Réinitialisation de votre mot de passe - TeachInspire"
- Lien: `https://domain.com/reset-password?token=${token}&lang=${userLang}`
- Expiration: 15 minutes
- Design cohérent avec identité visuelle

### Traductions

#### Ajouts dans constants.js
```javascript
auth: {
  forgotPassword: {
    title: { fr: "Mot de passe oublié", en: "Forgot Password" },
    subtitle: { fr: "Entrez votre email pour recevoir un lien", en: "Enter your email to receive a reset link" },
    emailPlaceholder: { fr: "Votre email", en: "Your email" },
    sendButton: { fr: "Envoyer le lien", en: "Send Reset Link" },
    backToLogin: { fr: "Retour à la connexion", en: "Back to Login" },
    success: { fr: "Email envoyé! Vérifiez votre boîte de réception", en: "Email sent! Check your inbox" }
  },
  resetPassword: {
    title: { fr: "Nouveau mot de passe", en: "New Password" },
    password: { fr: "Nouveau mot de passe", en: "New Password" },
    confirmPassword: { fr: "Confirmer le mot de passe", en: "Confirm Password" },
    resetButton: { fr: "Réinitialiser", en: "Reset Password" },
    success: { fr: "Mot de passe réinitialisé avec succès", en: "Password reset successfully" }
  }
}
```

## Plan d'implémentation par phases

### Phase 1: Backend Foundation (1-2h)
1. Créer table D1 `password_reset_tokens`
2. Implémenter endpoint `/api/auth/forgot-password`
3. Implémenter endpoint `/api/auth/reset-password`
4. Configurer service email (Mailgun/SendGrid)
5. Tester endpoints avec curl/Postman

### Phase 2: Frontend Core (1-2h)
1. Créer composant `ForgotPassword.js`
2. Créer composant `ResetPassword.js`
3. Ajouter méthodes dans `apiService.js`
4. Ajouter méthodes dans `AuthContext.js`
5. Intégrer traductions dans `constants.js`

### Phase 3: Integration (30min-1h)
1. Ajouter routes dans router principal
2. Modifier composant Login (lien mot de passe oublié)
3. Tester navigation complète
4. Ajuster responsive design

### Phase 4: Testing & Polish (30min)
1. Test flow complet FR/EN
2. Vérification sécurité (tokens, expiration)
3. Test edge cases (token invalide, expiré)
4. Validation UX et accessibilité

## Considérations sécurité

### Tokens
- UUID v4 cryptographiquement sécurisé
- Expiration courte (15 minutes)
- Usage unique (marqué used après utilisation)
- Nettoyage automatique tokens expirés

### Validation
- Rate limiting sur endpoints (max 3 tentatives/heure/IP)
- Validation email côté backend
- Pas d'énumération d'emails (toujours retourner succès)
- Hash passwords avec bcrypt (salt rounds: 12)

### Email
- Lien HTTPS uniquement
- Domain binding (vérifier origin)
- Pas d'info sensible dans URL (que le token)

## Estimation temps total: 3-5 heures
- Backend: 1-2h
- Frontend: 1-2h  
- Integration: 30min-1h
- Testing: 30min

## Prérequis techniques
- Accès à Cloudflare D1 pour créer table
- Compte Resend avec domaine vérifié
- Variable d'environnement `RESEND_API_KEY` dans Cloudflare Workers
- Domaine configuré dans Resend pour envoi emails