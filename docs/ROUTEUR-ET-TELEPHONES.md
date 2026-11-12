# Routeur, DHCP et téléphones : comment tout passe par NetWatch

NetWatch ne voit que les appareils qui lui envoient leurs requêtes DNS. Ce guide explique comment s'en
assurer, et ce que fait chaque type de téléphone quand il tente de contourner le filtre.

## 1. Réseau d'exemple

Les adresses ci-dessous sont un exemple ; remplacez-les par celles de votre réseau.

| Élément | Adresse | Rôle |
|---|---|---|
| DC01 | 192.168.1.10 | Contrôleur de domaine `corp.example.local`, **DNS et DHCP** actuels |
| SRV-APP | 192.168.1.11 | Serveur toujours allumé ; **NetWatch** (ports UDP/TCP 53 et TCP 8795 libres) |
| Passerelle | 192.168.1.1 | Routeur Internet |
| Postes | 192.168.1.x | PC, téléphones, tablettes, imprimantes |

Chaîne cible : appareil → NetWatch (SRV-APP) → DC01 → Internet. DC01 reste la référence pour les noms
internes et Active Directory ; NetWatch ne fait que relayer.

## 2. Option DNS du DHCP (l'étape qui change tout)

Sur DC01, console **DHCP** › IPv4 › Étendue 192.168.1.0 › **Options d'étendue** › 006 Serveurs DNS :

- mettre **192.168.1.11** en premier ;
- retirer 192.168.1.10 de la liste (sinon Windows peut l'interroger directement quand NetWatch tarde,
  et ces requêtes échappent au journal). NetWatch relaie lui-même vers DC01, rien n'est perdu.

Les baux se renouvellent d'eux-mêmes (souvent 8 jours : moitié du bail). Pour accélérer : `ipconfig /renew`
sur un PC, Wi-Fi off/on sur un téléphone. Vérification : `nslookup pornhub.com` sur un PC doit indiquer
`Serveur : 192.168.1.11`, et l'appareil apparaît dans **Appareils** avec sa requête signalée.

Si le Wi-Fi est fourni par un routeur ou des bornes avec leur **propre DHCP** (réseau séparé), y régler
l'option DNS de la même façon. Si ce Wi-Fi est sur un autre sous-réseau, NetWatch voit l'IP de chaque
téléphone mais pas sa MAC (identité par IP seulement) : nommez les appareils dans leur fiche.

## 3. Fermer les portes de sortie (routeur / pare-feu)

Un appareil peut ignorer le DHCP et utiliser un DNS fixé à la main (8.8.8.8, 1.1.1.1). Pour l'empêcher,
sur le routeur 192.168.1.1 (ou le pare-feu) :

- **bloquer le port 53 sortant (UDP et TCP)** pour tout le monde sauf SRV-APP et DC01 ;
- **bloquer le port 853 sortant** (DNS-over-TLS, utilisé par le « DNS privé » Android) ;
- facultatif : bloquer le port 443 vers les adresses des grands DoH publics (NetWatch bloque déjà leurs
  noms, ce qui suffit en pratique).

Résultat : un appareil avec un DNS « en dur » n'a plus de résolution de noms tant qu'il ne repasse pas
par le DHCP. Dans NetWatch, la page **PC (agents)** signale les PC dont le DNS ne pointe pas vers NetWatch.

## 4. Wi-Fi invités pour les téléphones personnels

Recommandation : un SSID « Entreprise-Invités » isolé du réseau de production (les routeurs et bornes le
font en quelques clics), dont le DHCP distribue **192.168.1.11** comme DNS et dont le pare-feu bloque 53/853
sortants. Les téléphones personnels sont filtrés et journalisés sans jamais toucher aux serveurs, et
l'avis aux employés peut dire clairement « le Wi-Fi invités est filtré et journalisé ».

## 5. Ce que fait chaque téléphone face au filtre

**iPhone / iPad — relais privé iCloud (iCloud+)** : chiffre DNS et trafic vers Apple, ce qui masque tout.
NetWatch répond NXDOMAIN à `mask.icloud.com` et `mask-h2.icloud.com`, la méthode qu'Apple documente pour
les réseaux d'entreprise : l'iPhone affiche « Relais privé non pris en charge par ce réseau » et navigue
normalement, donc visiblement.

**iPhone — DNS chiffré par profil** (rare, nécessite une app ou un profil de configuration) : les
fournisseurs connus sont bloqués par nom (catégorie *Contournement*), l'app perd sa résolution et
l'utilisateur doit la désactiver.

**Android — « DNS privé »** : en mode *Automatique*, le téléphone tente le port 853 vers le DNS du DHCP
(NetWatch ne l'offre pas) puis retombe sur le DNS normal : filtré. En mode *Nom d'hôte* (`dns.google`,
`one.one.one.one`…), ce nom est bloqué (NXDOMAIN) : Android affiche « Impossible d'accéder au serveur DNS
privé » et coupe Internet sur le Wi-Fi jusqu'à ce que l'option soit remise à *Automatique* ou *Désactivé*.
C'est l'effet voulu ; l'employé peut vous le demander.

**Navigateurs (Chrome, Edge, Firefox, Brave) — DNS-over-HTTPS** : en mode automatique ils n'utilisent DoH
que si le DNS du réseau est un fournisseur DoH connu (ce n'est pas le cas de NetWatch) ; en mode manuel les
fournisseurs sont bloqués par nom. Firefox vérifie en plus `use-application-dns.net` : NetWatch répond
NXDOMAIN, Firefox désactive DoH de lui-même. Sur les PC de l'entreprise, l'agent impose DoH désactivé
par stratégie.

**VPN sur le téléphone** : tout le trafic (DNS compris) part chiffré vers le fournisseur VPN. NetWatch voit
la première requête (`*.nordvpn.com`, `*.protonvpn.com`…) et la signale en catégorie *VPN* (alerte par
défaut ; mettre *Bloquer* si la politique interdit les VPN sur le Wi-Fi). Comme pour les données
cellulaires, la navigation à l'intérieur du VPN n'est pas visible : la seule réponse est la politique
d'entreprise, pas la technique.

**Données cellulaires** : hors de portée de toute solution réseau. Invisible, et normal.

## 6. Adresses MAC aléatoires

Depuis iOS 14 et Android 10, un téléphone présente une adresse MAC « privée » différente par réseau Wi-Fi,
mais **stable** sur un réseau donné (sauf si l'option « rotation » est activée). NetWatch l'indique par le
fabricant *Adresse privée (aléatoire)* et devine *Téléphone / tablette*. Donnez un nom et un propriétaire à
l'appareil une fois pour toutes dans sa fiche ; l'historique suit cette adresse.

## 7. Vérifier que tout est en place

1. Sur un PC : `nslookup use-application-dns.net` → `*** … can't find … : Non-existent domain` (filtre actif).
2. Sur un téléphone en Wi-Fi : ouvrir `http://neverssl.com` (doit marcher) puis `http://pornhub.com`
   (page « Accès bloqué » si la catégorie est sur *Bloquer*, sinon alerte dans le tableau de bord).
3. Dans **Appareils** : le téléphone apparaît, avec sa MAC et un nom (s'il en diffuse un).
4. Dans **PC (agents)** : chaque PC de l'entreprise affiche « DNS via NetWatch : Oui ».
