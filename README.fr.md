# NetWatch — surveillance et filtrage du réseau de l’entreprise

NetWatch est un serveur DNS « de passage » installé sur un serveur de l'entreprise. Chaque PC, téléphone ou
tablette qui utilise le Wi-Fi ou le réseau filaire lui demande où se trouvent les sites qu'il consulte.
NetWatch note ces demandes par appareil, les compare à des listes de sites (contenu explicite, jeux
d'argent, logiciels malveillants, hameçonnage, contournement de filtre…), alerte, et peut bloquer.

Tout est en Python standard (aucune installation de bibliothèque), les données restent sur le serveur
(SQLite), l'interface est en français sur `http://<serveur>:8795/`.

## Ce que NetWatch voit, et ce qu'il ne voit pas

| Il voit | Il ne voit pas |
|---|---|
| Le **nom de domaine** demandé (`www.pornhub.com`), l'heure, l'appareil (IP, MAC, nom, fabricant) | Le contenu des pages, les recherches, les mots de passe (tout est chiffré en HTTPS) |
| Le nombre de requêtes par domaine, par appareil et par jour | L'URL exacte à l'intérieur d'un site |
| Sur les PC avec l'agent : le PC, l'utilisateur connecté, ses serveurs DNS | Captures d'écran, frappes clavier : jamais |
| Les tentatives de contournement (DNS chiffré, relais privé iCloud) | Le trafic d'un téléphone qui utilise ses **données cellulaires** au lieu du Wi-Fi |

Un appareil qui n'utilise pas NetWatch comme DNS n'est pas vu : d'où l'importance de l'étape DHCP et des
recommandations du guide [docs/ROUTEUR-ET-TELEPHONES.md](docs/ROUTEUR-ET-TELEPHONES.md).

## Comment ça marche

```
téléphone / PC ──(DNS, port 53)──► NetWatch (SRV-APP 192.168.1.11)
                                      │  1. classe le domaine (règles, listes UT1/StevenBlack, mots-clés)
                                      │  2. journalise (appareil, domaine, jour, compteur)
                                      │  3. alerte / bloque selon la catégorie
                                      └──(relais)──► DNS du domaine (DC01 192.168.1.10) ──► Internet
```

- **Bloquer** : le domaine ne se résout pas. En HTTP l'employé voit la page « Accès bloqué » ; en HTTPS le
  navigateur affiche une erreur de connexion. Les domaines de contournement reçoivent NXDOMAIN, ce qui
  désactive proprement le DNS chiffré de Firefox et le relais privé iCloud sur le réseau.
- **Alerter** : accès permis, mais événement enregistré (une entrée par appareil et domaine par minute) et
  courriel facultatif.
- **Journal seulement** : compté dans le journal (réseaux sociaux, vidéo), sans alerte.

Par défaut : contenu explicite, rencontres, jeux d'argent, drogues, haine → **alerte** ;
logiciels malveillants, hameçonnage, minage caché, logiciel espion, contournement du filtre → **bloqué**.
Tout se change dans **Listes**, avec effet immédiat.

## Installation sur le serveur (exemple : SRV-APP)

Rien à installer avant si le paquet contient son propre Python (dossier `python\`, Python 3.9 ou plus
récent, bibliothèque standard seulement). Le port UDP 53 doit être libre sur SRV-APP (si le port 80 est
occupé, la page de blocage se désactive d'elle-même).

1. Le paquet est sur le partage : `\\DC01\Public\NetWatch`.
2. Sur SRV-APP, dans PowerShell **en tant qu'administrateur** :
   ```powershell
   powershell -ExecutionPolicy Bypass -File \\DC01\Public\NetWatch\install.ps1
   ```
   Le script copie dans `C:\NetWatch` (avec son Python), ouvre le pare-feu (UDP/TCP 53, TCP 8795, TCP 80),
   crée la tâche planifiée « NetWatch » (compte SYSTEM, au démarrage, relance automatique) et la lance.
3. Ouvrir `http://192.168.1.11:8795/` et **choisir le mot de passe administrateur** (premier écran).
4. Dans **Listes**, cliquer **Mettre à jour les listes** : téléchargement des listes UT1 (Université
   Toulouse Capitole, 26 Mo) et StevenBlack, puis des préfixes fabricants IEEE. Environ une minute.
   La mise à jour se refait seule tous les 7 jours.
5. Tester **sans rien changer pour les autres**, depuis n'importe quel PC :
   ```powershell
   nslookup www.pornhub.com 192.168.1.11
   nslookup use-application-dns.net 192.168.1.11
   ```
   La première doit répondre une adresse et apparaître dans **Alertes** ; la seconde doit répondre
   « Non-existent domain ». Pour un essai d'une journée sur un seul appareil, régler à la main son DNS
   sur `192.168.1.11` (PC : Paramètres › Réseau › Modifier les options DNS ; téléphone : Wi-Fi › réglages
   du réseau › DNS manuel).
6. Quand tout va bien : faire passer tous les appareils par NetWatch (section suivante).

Mise à jour du logiciel : relancer `.\install.ps1` depuis le nouveau dossier ; `C:\NetWatch\data`
(base, journal, clé de session) et `config.json` sont conservés. Désinstallation : `.\install.ps1 -Uninstall`.

Test sans toucher au port 53 (sur n'importe quel PC) : `run.bat --dns-port 5300 --web-port 8796 --no-blockpage`.

## Faire passer tous les appareils par NetWatch

Dans l'exemple, le DHCP de l'entreprise tourne sur **DC01 (192.168.1.10)** et distribue DC01 comme DNS.

1. Sur DC01 : **Gestionnaire de serveur › Outils › DHCP › IPv4 › Étendue › Options d'étendue**,
   option **006 Serveurs DNS** : remplacer par `192.168.1.11` (SRV-APP). Garder DC01 en second serveur
   seulement si l'on accepte qu'un appareil puisse le contacter directement (il contourne alors NetWatch) ;
   recommandation : **192.168.1.11 seul**. NetWatch relaie vers DC01, donc les noms du domaine
   `corp.example.local` et Active Directory continuent de fonctionner.
2. Sur un PC : `ipconfig /renew` puis `nslookup pornhub.com` → l'appareil doit apparaître dans **Appareils**.
   Les téléphones suivent à leur prochaine reconnexion au Wi-Fi (ou bascule Wi-Fi off/on).
3. Si le Wi-Fi des employés est sur un autre routeur avec son propre DHCP, y mettre la même option DNS.
4. Recommandé sur le routeur/pare-feu : bloquer en sortie les ports **53** et **853** sauf depuis
   SRV-APP et DC01. Un appareil avec un DNS « en dur » (8.8.8.8) ne peut alors plus contourner.

Les serveurs (DC01, SRV-APP) gardent leur DNS statique actuel : ils n'ont pas besoin de passer par NetWatch.

## Les PC de l'entreprise (agent)

Page **PC (agents)** : copier la commande affichée et l'exécuter en administrateur sur chaque PC. L'agent :

- crée la tâche planifiée « NetWatch Agent » (à l'ouverture de session puis toutes les 5 minutes) qui envoie
  le nom du PC, **l'utilisateur connecté**, l'IP, la MAC, les serveurs DNS en usage et la version de Windows ;
- désactive le DNS chiffré (DoH) dans Chrome, Edge, Firefox et Windows par stratégie locale, pour que le
  filtre ne soit pas contourné ;
- laisse le DNS fourni par le DHCP (`-DnsMode Static` force SRV-APP comme DNS du PC).

Le tableau **PC (agents)** montre si chaque PC passe bien par NetWatch (« DNS via NetWatch : Oui/Non ») et
si les politiques sont appliquées. Désinstallation : même commande avec `-Uninstall`.

## Les téléphones

Les téléphones personnels sont vus dès qu'ils utilisent le Wi-Fi (MAC souvent « adresse privée », c'est
normal : donnez-leur un nom et un propriétaire dans la fiche de l'appareil). Les contournements courants
sont traités : relais privé iCloud (désactivé par la méthode documentée d'Apple), DNS privé Android et DoH
(fournisseurs bloqués). Un téléphone en données cellulaires n'est pas visible : c'est une limite de toute
solution réseau. Détails dans [docs/ROUTEUR-ET-TELEPHONES.md](docs/ROUTEUR-ET-TELEPHONES.md).

## Utilisation

Le **manuel complet**, avec captures d'écran, est dans l'application : menu **Manuel**, ou le bouton
**? Aide** en haut de chaque page qui ouvre le bon chapitre. Les captures se refont avec
`python qa\manual_shots.py` (copie de démonstration privée, données fictives, rien ne touche le réseau).

- **Tableau de bord** : appareils actifs, requêtes, alertes et blocages du jour, dernières alertes,
  appareils et domaines signalés, 14 derniers jours. Liste de mise en service tant que tout n'est pas prêt.
- **Appareils** : tout ce qui interroge NetWatch, avec statut en ligne, type (PC, téléphone…), IP, MAC,
  fabricant, requêtes et signalements du jour. Cliquer un appareil : fiche (nom affiché, propriétaire,
  type, ignorer), domaines signalés, tous les domaines, événements ; boutons **Autoriser** / **Bloquer**
  sur chaque domaine.
- **Alertes** : filtres par appareil, catégorie, action, période, texte.
- **Journal** : domaines consultés par appareil et par jour ; **Exporter CSV** (Excel, séparateur `;`).
- **Listes** : action par catégorie, sources et mise à jour, test d'un domaine, règles manuelles
  (autoriser un faux positif, bloquer un site précis), mots-clés de repli.
- **Réglages** : relais DNS, page de blocage, rétention (90 jours par défaut), courriels, mot de passe,
  état du système, journal système, documents.

## Courriels d'alerte

Réglages › Courriels : activer, destinataires, `smtp.gmail.com` port 587, compte Gmail et **mot de passe
d'application**. Une alerte par appareil et par catégorie
toutes les 30 minutes au plus (regroupement réglable), rapport quotidien facultatif à l'heure choisie.
Le mot de passe est stocké dans `config.json` sur le serveur, jamais affiché dans l'interface.

## Cadre légal et transparence (Québec)

Surveiller l'usage du réseau de l'entreprise est permis, à condition d'en **informer** les employés
(Loi 25 et Charte des droits et libertés de la personne : attente raisonnable de vie privée, finalité
sérieuse, moyen proportionné). Concrètement :

1. afficher et faire signer l'avis fourni : [docs/AVIS-SURVEILLANCE-RESEAU.md](docs/AVIS-SURVEILLANCE-RESEAU.md) ;
2. ne garder que ce qui est nécessaire (rétention 90 jours, pas de contenu de pages) ;
3. réserver l'accès au tableau de bord à la direction (mot de passe) ;
4. pour les téléphones personnels, préférer un Wi-Fi « invités » filtré, séparé du réseau de production.

Une preuve recueillie sans avis préalable peut être jugée irrecevable ; l'avis protège l'entreprise.

## Fichiers

```
netwatch.py          lanceur (python netwatch.py [--dns-port] [--web-port] [--no-blockpage] [--service])
app/                 dnsproxy (serveur DNS), classify, store (SQLite), devices (ARP, noms, fabricants),
                     lists_update (UT1, hosts, OUI), alerts (SMTP), web (API + page de blocage), core
static/              interface (index.html, app.js, style.css), manuel.html + manuel/img (manuel intégré)
seeds/               listes intégrées (adulte, contournement, mots-clés, fabricants)
agent/               Install-NetWatchAgent.ps1 (PC de l'entreprise)
install.ps1          installation / mise à jour / désinstallation sur le serveur
config.json          réglages et secrets (créé au premier démarrage ; modèle : config.example.json)
data/                netwatch.db (SQLite), secret.key, netwatch.log (mode service)
qa/test_netwatch.py  tests automatiques : python qa\test_netwatch.py
```

## Dépannage

- **« DNS inactif » / port 53 occupé** : `netstat -ano | findstr :53` sur le serveur ; si un autre
  service DNS tourne, installer NetWatch sur une autre machine toujours allumée, ou changer `dns.bind`
  vers une seconde adresse IP de la carte réseau.
- **Aucun appareil n'apparaît** : l'option DNS du DHCP n'a pas été changée, ou les appareils n'ont pas
  renouvelé leur bail (`ipconfig /renew`, Wi-Fi off/on).
- **Un appareil affiche « Non » dans DNS via NetWatch** : DNS fixé à la main sur le PC ; relancer
  l'agent avec `-DnsMode Static`, ou bloquer le port 53 sortant sur le routeur.
- **Faux positif** (site légitime signalé) : Listes › Règles manuelles › Autoriser, ou bouton
  **Autoriser** sur l'alerte.
- **Les noms internes ne marchent plus** : Réglages › DNS › relais doit contenir `192.168.1.10` (DC01).
- **Liste en « Erreur : CERTIFICATE_VERIFY_FAILED »** : le serveur ne connaît pas l'autorité du site
  (Windows Server télécharge ces certificats racines à la demande, Python non). NetWatch embarque la liste
  des autorités de Mozilla (`seeds\cacert.pem`, curl.se) en plus de celles de Windows ; la vérification
  reste active. Si l'erreur revient dans quelques années, remplacer ce fichier par la version à jour de
  https://curl.se/ca/cacert.pem et relancer l'installation.
- **Journal du service** : `C:\NetWatch\data\netwatch.log` ; journal système dans Réglages.
