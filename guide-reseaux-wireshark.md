# Maîtriser les réseaux avec Wireshark

## Guide complet de théorie, capture, analyse et dépannage réseau

**Auteur : Manus AI**  
**Public visé : débutant motivé à niveau intermédiaire/avancé**  
**Environnement privilégié : Linux, avec indications Windows lorsque nécessaire**

> **Objectif du guide.** Comprendre ce qui se passe réellement sur un réseau, savoir capturer le trafic dans un environnement autorisé, interpréter les protocoles couche par couche, isoler une anomalie et produire une conclusion techniquement défendable avec Wireshark.

Wireshark n’est pas un outil magique qui « montre Internet ». C’est un analyseur de protocoles : il enregistre des trames, les décode selon les protocoles connus, puis permet de filtrer, reconstruire et comparer les échanges. La compétence essentielle n’est donc pas de mémoriser des centaines de filtres, mais de relier **un symptôme**, **une hypothèse réseau**, **des paquets observables** et **une preuve**.

---

## Sommaire

1. Cadre légal, éthique et méthode de travail  
2. Les objectifs d’apprentissage  
3. Comprendre le modèle réseau avant de capturer  
4. Les fondamentaux indispensables : Ethernet, IP, TCP, UDP et services  
5. Installer et préparer Wireshark sous Linux et Windows  
6. Comprendre l’interface et le cycle d’analyse  
7. Filtres de capture et filtres d’affichage  
8. Lire une trame couche par couche  
9. Analyser les protocoles les plus importants  
10. Dépanner méthodiquement avec Wireshark  
11. Statistiques, flux, graphiques et reconstruction  
12. Wireshark en ligne de commande : TShark et utilitaires  
13. Limites réelles : chiffrement, offloading, Wi-Fi, VLAN et points de capture  
14. Travaux pratiques progressifs  
15. Méthode d’analyse orientée CTF et défense  
16. Programme d’entraînement sur trente jours  
17. Fiche mémo finale  
18. Références

---

# 1. Cadre légal, éthique et méthode de travail

Une capture réseau peut contenir des identifiants, des cookies, des noms d’hôtes, des adresses internes, des requêtes DNS, des fichiers ou des données personnelles. Il faut donc capturer uniquement un réseau, une machine ou un fichier PCAP pour lesquels vous disposez d’une **autorisation explicite**. Dans un laboratoire, utilisez votre propre machine, une machine virtuelle, un réseau isolé ou un PCAP public prévu pour l’apprentissage.

L’analyse passive est différente d’une intrusion active. Lire un fichier de capture fourni pour un exercice n’autorise pas à attaquer le système d’origine. De même, observer ses propres paquets HTTP dans un laboratoire n’autorise pas à intercepter ceux d’un voisin, d’une entreprise ou d’un réseau Wi-Fi public.

Adoptez dès le début une discipline de preuve : notez la date, la machine, l’interface, le point de capture, le filtre utilisé, le fuseau horaire, la version de Wireshark et les limites connues. Une conclusion sérieuse doit distinguer ce qui est **observé**, ce qui est **déduit** et ce qui reste **à vérifier**.

| Catégorie | Exemple | Formulation rigoureuse |
|---|---|---|
| Observation | Trois segments TCP sont retransmis | « La capture contient trois événements signalés comme retransmission TCP. » |
| Hypothèse | Le réseau perd des paquets | « Cela peut indiquer une perte, mais il faut vérifier le point de capture, les timestamps et les offloads. » |
| Conclusion | Le serveur est lent | « Le délai serveur mesuré entre la requête et la réponse est élevé dans cette transaction précise. » |
| Limite | TLS chiffre le contenu | « Le contenu applicatif n’est pas lisible sans secrets de session ou mécanisme de déchiffrement autorisé. » |

---

# 2. Les objectifs d’apprentissage

À la fin de ce guide, vous devez être capable de dessiner le chemin logique d’un paquet, de reconnaître les couches Ethernet/IP/transport/application, d’identifier les rôles client-serveur et de distinguer une absence de réponse, une réponse négative, un refus TCP et une retransmission.

Vous saurez également choisir entre un **filtre de capture**, appliqué pendant l’enregistrement, et un **filtre d’affichage**, appliqué après la capture. Wireshark documente ces deux langages séparément : les filtres de capture utilisent la syntaxe libpcap, tandis que les filtres d’affichage utilisent le langage propre de Wireshark [1] [2].

Enfin, vous apprendrez à construire un raisonnement reproductible : définir le problème, localiser les endpoints, suivre la conversation, mesurer les délais, examiner les erreurs et produire un rapport court accompagné des paquets de preuve.

## Pré-requis recommandés

Vous pouvez commencer sans être expert, mais les notions suivantes accéléreront fortement la progression : adresses IPv4 et IPv6, masque CIDR, ports TCP/UDP, résolution DNS, modèle OSI ou TCP/IP, commandes Linux de base et lecture d’un terminal.

Les outils complémentaires utiles sont `ip`, `ss`, `ping`, `traceroute` ou `tracepath`, `dig`, `curl`, `nc`, `tcpdump`, `tshark`, `capinfos` et `editcap`. Ils ne remplacent pas Wireshark ; ils permettent de vérifier une hypothèse ou d’automatiser l’analyse.

---

# 3. Comprendre le modèle réseau avant de capturer

## 3.1 Le modèle en couches

Un paquet n’est pas un bloc unique. Il est généralement constitué de plusieurs enveloppes. Sur un réseau Ethernet classique, une application produit des données qui sont transportées par TCP ou UDP, encapsulées dans IP, puis dans une trame Ethernet.

| Couche pédagogique | Question à poser | Exemples observables dans Wireshark |
|---|---|---|
| Application | Quel service parle et avec quel contenu ? | DNS, HTTP, TLS, SSH, DHCP |
| Transport | Comment les processus échangent-ils ? | TCP, UDP, ports, séquence, ACK |
| Internet | Où le paquet doit-il aller ? | IPv4, IPv6, ICMP, TTL/Hop Limit |
| Liaison | Sur quel segment local circule-t-il ? | Ethernet, ARP, VLAN, Wi-Fi |
| Physique | Le signal est-il transporté ? | généralement non visible directement dans un PCAP Ethernet |

L’encapsulation explique pourquoi une seule ligne Wireshark peut afficher `Ethernet II`, `Internet Protocol Version 4`, `Transmission Control Protocol` et `Hypertext Transfer Protocol`. Il s’agit d’un même paquet décodé à plusieurs niveaux, pas de quatre paquets indépendants.

## 3.2 Adresses, ports et identifiants de flux

Une adresse MAC identifie normalement une interface sur un segment de couche 2, tandis qu’une adresse IP identifie un endpoint au niveau IP. Un port identifie un service ou un socket dans le contexte d’une machine. Une connexion TCP est généralement repérée par le quadruplet :

```text
IP source : port source -> IP destination : port destination
```

Le port source est souvent éphémère côté client, alors que le serveur écoute sur un port connu ou configuré. Il ne faut toutefois pas déduire le rôle uniquement du numéro de port : un service peut fonctionner sur un port non standard, et Wireshark peut afficher un protocole supposé en fonction du port ou d’un décodage heuristique.

## 3.3 IPv4, sous-réseaux, passerelle et NAT

Une adresse IPv4 possède 32 bits. La notation CIDR, par exemple `192.168.10.0/24`, indique que les 24 premiers bits représentent le préfixe réseau et que les 8 bits restants servent aux hôtes. Dans une capture, l’adresse source et l’adresse destination permettent de déterminer si l’échange est local ou s’il doit passer par une passerelle.

La passerelle par défaut est généralement visible indirectement : pour atteindre une adresse située hors du sous-réseau local, l’hôte résout souvent l’adresse MAC de la passerelle grâce à ARP, puis envoie la trame Ethernet à cette MAC tandis que la destination IP reste celle du serveur distant. Avec NAT, le paquet peut changer d’adresse et de port lorsqu’il traverse la passerelle ; le point de capture détermine donc quelle version de l’adresse vous observez.

## 3.4 IPv6

IPv6 utilise des adresses de 128 bits et un champ `Next Header` pour enchaîner l’en-tête IPv6, d’éventuels en-têtes d’extension et le protocole de couche supérieure [3]. En pratique, il faut examiner les adresses globales, link-local, multicast, le champ `Hop Limit`, la découverte de voisins et ICMPv6. Une analyse qui ne regarde que `ip.addr` peut manquer une partie du trafic si le réseau utilise IPv6 ; ajoutez alors `ipv6.addr`, `icmpv6`, `ndp` et les filtres associés.

---

# 4. Les fondamentaux indispensables

## 4.1 Ethernet et ARP

Ethernet transporte des trames identifiées par des adresses MAC source et destination ainsi qu’un champ EtherType. Une trame peut être unicast, broadcast ou multicast. Une adresse de broadcast Ethernet est `ff:ff:ff:ff:ff:ff`.

ARP associe une adresse IPv4 à une adresse MAC sur un réseau local. Une requête ARP demande généralement « Qui possède cette IPv4 ? », et la réponse indique la MAC correspondante. ARP n’est pas routé : il fonctionne sur le segment local. Une anomalie ARP peut donc expliquer une absence de connectivité locale, une résolution incohérente ou un comportement de type empoisonnement ; ne concluez jamais à une attaque sur la seule présence d’un paquet ARP inhabituel.

Filtres utiles :

```text
arp
arp.opcode == 1
arp.opcode == 2
arp.duplicate-address-detected
eth.addr == 00:11:22:33:44:55
```

## 4.2 IP et ICMP

IPv4 contient notamment les adresses, le protocole encapsulé, la durée de vie `TTL`, la longueur, l’identification et les informations de fragmentation. Le TTL est décrémenté par les routeurs ; il sert à empêcher qu’un paquet boucle indéfiniment. Une valeur faible ou des messages ICMP `Time Exceeded` peuvent aider à comprendre un chemin, notamment avec `traceroute`.

ICMP transporte des messages de contrôle et d’erreur, par exemple Echo Request/Echo Reply, Destination Unreachable, Time Exceeded et Packet Too Big. Un ping qui échoue ne prouve pas qu’un service est indisponible : le pare-feu peut filtrer ICMP alors que TCP/HTTPS fonctionne. Inversement, un ping réussi ne prouve pas qu’un service applicatif écoute.

Filtres utiles :

```text
icmp
icmp.type == 8
icmp.type == 0
icmpv6
ip.ttl < 10
ip.flags.mf == 1
ip.fragment
```

## 4.3 TCP

TCP fournit un flux d’octets fiable et ordonné, utilise des numéros de séquence et d’acquittement, et contrôle le flux grâce à une fenêtre. Ces propriétés sont décrites dans le standard TCP moderne [4]. Le handshake classique est :

```text
Client -> Serveur : SYN
Serveur -> Client : SYN, ACK
Client -> Serveur : ACK
```

Les indicateurs principaux sont `SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`, `ECE` et `CWR`. Un `RST` peut signifier qu’un port est fermé, qu’une connexion a été interrompue ou qu’un équipement intermédiaire a rejeté l’échange. Il ne faut pas l’interpréter sans regarder la direction, le moment et le contexte.

La séquence TCP s’analyse avec `tcp.seq`, `tcp.ack`, `tcp.len`, `tcp.window_size_value`, `tcp.analysis.retransmission`, `tcp.analysis.lost_segment`, `tcp.analysis.duplicate_ack` et `tcp.analysis.zero_window`. Wireshark calcule plusieurs champs d’analyse ; ils sont des aides d’interprétation, pas une vérité indépendante du point de capture.

Filtres utiles :

```text
tcp
tcp.port == 443
tcp.flags.syn == 1 && tcp.flags.ack == 0
tcp.flags.reset == 1
tcp.analysis.retransmission
tcp.analysis.fast_retransmission
tcp.analysis.lost_segment
tcp.analysis.duplicate_ack
tcp.analysis.zero_window
tcp.stream == 0
```

## 4.4 UDP

UDP est un protocole de datagrammes avec un mécanisme minimal ; la livraison, l’ordre et la protection contre les doublons ne sont pas garantis par UDP lui-même [5]. Il est fréquent dans DNS, DHCP, NTP, VoIP, certains tunnels et de nombreux protocoles modernes.

L’absence de handshake ne signifie pas absence de protocole ou absence de réponse. Pour analyser UDP, associez les requêtes et les réponses à partir des adresses, ports, identifiants applicatifs et timestamps. Une perte peut être visible seulement si l’application possède un identifiant de transaction ou si une réponse attendue manque.

Filtres utiles :

```text
udp
udp.port == 53
udp.length > 1200
udp contains 81:60:03
```

## 4.5 DNS

DNS traduit des noms en informations comme des adresses, des alias ou des serveurs de messagerie. Dans une capture, cherchez la requête, le type demandé, l’identifiant de transaction, le serveur interrogé, le code de réponse et le délai jusqu’à la réponse.

Filtres utiles :

```text
dns
dns.flags.response == 0
dns.flags.response == 1
dns.qry.name
dns.qry.name == "example.org"
dns.response_to
dns.time > 0.5
dns.flags.rcode != 0
```

Une réponse DNS négative n’est pas identique à une absence de réponse. `NXDOMAIN` indique que le nom n’existe pas selon le serveur interrogé ; un timeout peut signaler une perte, un filtrage, un serveur lent ou un mauvais chemin. Vérifiez aussi DNS sur TCP, DNS over TLS et DNS over HTTPS, qui rendent l’observation plus limitée au niveau du contenu.

## 4.6 DHCP

Dans IPv4, DHCP utilise généralement UDP et suit une séquence pédagogique `Discover`, `Offer`, `Request`, `ACK`. La capture permet d’identifier le client, le serveur, le relay éventuel, l’adresse proposée, la durée du bail, la passerelle, les DNS et les options.

Filtres utiles :

```text
dhcp
dhcp.option.dhcp == 1
dhcp.option.dhcp == 2
dhcp.option.dhcp == 3
dhcp.option.dhcp == 5
dhcp.option.hostname
dhcp.ip.your
```

Les noms exacts de certains champs peuvent évoluer. Pour confirmer un champ disponible dans votre version, sélectionnez-le dans le panneau de détails et utilisez **Apply as Filter**, ou recherchez dans **View → Internals → Supported Protocols**. La documentation de Wireshark précise que les champs d’affichage correspondent aux champs ajoutés par les dissectors [1].

## 4.7 HTTP et HTTPS/TLS

HTTP en clair expose les méthodes, URI, en-têtes et parfois les données applicatives. HTTPS encapsule généralement HTTP dans TLS. TLS vise notamment l’authentification, la confidentialité et l’intégrité du canal [6]. Vous pourrez donc souvent voir les métadonnées de connexion, le serveur, le port, le handshake et des tailles de données, mais pas le contenu applicatif sans secrets autorisés.

Filtres HTTP :

```text
http
http.request
http.response
http.request.method == "GET"
http.request.uri contains "login"
http.host
http.response.code >= 400
http contains "password"
```

Filtres TLS :

```text
tls
tls.handshake
tls.handshake.type == 1
tls.handshake.type == 2
tls.record
tls.alert_message
ssl
```

Dans TLS 1.3, une partie importante des messages postérieurs à `ServerHello` est chiffrée, ce qui réduit la quantité de contenu lisible directement dans une capture [6]. Pour déchiffrer une capture de votre propre application, utilisez un fichier de clés de session ou une configuration prévue à cet effet ; ne cherchez pas à contourner le chiffrement de tiers.

---

# 5. Installer et préparer Wireshark

## 5.1 Linux Debian/Ubuntu/Mint

Sous Debian, Ubuntu ou Linux Mint :

```bash
sudo apt update
sudo apt install wireshark tshark tcpdump
wireshark --version
tshark --version
```

Pendant l’installation, le système peut demander si les utilisateurs non superutilisateurs doivent pouvoir capturer des paquets. Choisissez cette option uniquement si vous comprenez que l’accès à la capture est sensible, puis ajoutez votre compte au groupe approprié si votre distribution le recommande. Après modification d’un groupe, ouvrez une nouvelle session ou utilisez `newgrp`.

Vérifiez les interfaces disponibles :

```bash
ip -br link
ip -br addr
tshark -D
```

L’interface `lo` correspond à la boucle locale. Une connexion à `127.0.0.1` ou `::1` n’apparaîtra pas forcément sur l’interface Ethernet ou Wi-Fi ; elle doit être capturée sur `lo`.

## 5.2 Windows

Installez Wireshark depuis le site officiel et acceptez l’installation de Npcap uniquement si vous souhaitez capturer du trafic. Évitez de télécharger l’installeur depuis un miroir inconnu. Lancez Wireshark avec les permissions nécessaires et vérifiez la liste des interfaces : Ethernet, Wi-Fi, VPN, loopback et interfaces virtuelles peuvent avoir des noms différents.

## 5.3 Choisir le bon point de capture

Sur une machine, capturez en priorité l’interface qui porte effectivement le trafic : Wi-Fi pour une connexion sans fil, Ethernet pour une liaison filaire, interface VPN pour un tunnel, `lo` pour le trafic local. Sur un commutateur, le mode promiscuous ne suffit pas à voir toutes les conversations : un switch ne copie pas automatiquement les trames des autres ports. Il faut un port miroir/SPAN, un TAP ou un point de capture situé sur le chemin.

> **Règle pratique :** si la capture ne contient pas le paquet au bon endroit, aucun filtre ni aucune analyse ne pourra le reconstituer.

## 5.4 Première capture contrôlée

Créez un dossier de laboratoire :

```bash
mkdir -p ~/lab-wireshark/captures
cd ~/lab-wireshark
```

Listez les interfaces :

```bash
tshark -D
```

Capturez ensuite quelques paquets sur l’interface appropriée, en remplaçant `2` par le numéro réel :

```bash
sudo dumpcap -i 2 -a duration:20 -w captures/premiere_capture.pcapng
```

Ouvrez le fichier :

```bash
wireshark captures/premiere_capture.pcapng
```

Le format `pcapng` est le format natif courant de Wireshark et TShark ; il peut contenir des informations de capture supplémentaires par rapport à un simple PCAP [7].

---

# 6. Comprendre l’interface et le cycle d’analyse

L’interface principale comporte généralement une liste de paquets, un panneau de détails du paquet sélectionné et une vue hexadécimale. La ligne de paquet est un résumé ; les détails permettent de descendre dans les champs ; l’hexadécimal sert à vérifier les octets réellement présents.

## 6.1 Le cycle de travail en huit étapes

### Étape 1 : définir la question

Ne commencez pas par « regarder tout le trafic ». Formulez une question : « Pourquoi la résolution DNS est-elle lente ? », « Le serveur refuse-t-il la connexion ? », « Le client retransmet-il ? », « Quelle requête précède la réponse 500 ? ».

### Étape 2 : préserver l’original

Travaillez sur une copie du PCAP et conservez l’original en lecture seule. Ajoutez un nom explicite, une date et, si possible, un hash :

```bash
sha256sum capture_originale.pcapng
cp capture_originale.pcapng travail.pcapng
```

### Étape 3 : comprendre le volume

Commencez par les informations globales :

```bash
capinfos travail.pcapng
```

Observez la durée, le nombre de paquets, la première et la dernière date, le type d’encapsulation, le snaplen et le débit moyen.

### Étape 4 : réduire le bruit

Utilisez un filtre d’affichage pour isoler un protocole, une adresse, un flux ou un événement. N’écrasez pas la capture originale en appliquant un filtre ; le filtre d’affichage ne supprime pas les paquets, il masque ceux qui ne correspondent pas.

### Étape 5 : identifier les endpoints

Utilisez **Statistics → Endpoints** et **Statistics → Conversations**. Cherchez les adresses les plus actives, les ports, la direction et les durées. Une adresse très présente peut être un DNS, une passerelle, un serveur de contenu, un proxy ou une machine compromise ; le volume seul ne suffit pas à conclure.

### Étape 6 : suivre un flux

Sélectionnez un paquet, clic droit, puis **Follow → TCP Stream**, **UDP Stream** ou le type proposé. Cela permet de replacer les messages dans le contexte d’une conversation et de voir les numéros de flux.

### Étape 7 : mesurer

Examinez `frame.time_delta`, `tcp.time_delta`, `dns.time`, les champs de réponse associée et les graphes de débit. Privilégiez des mesures reproductibles à des impressions visuelles.

### Étape 8 : documenter la preuve

Notez les numéros de paquets, le filtre exact, les timestamps relatifs et les limites. Une phrase comme « le serveur est lent » devient « dans le flux TCP 12, la requête client au paquet 184 est suivie de la première réponse serveur au paquet 205, avec un délai mesuré de 1,42 s ».

---

# 7. Filtres de capture et filtres d’affichage

## 7.1 La distinction fondamentale

Un **filtre de capture** est appliqué pendant la capture. Les paquets qui ne correspondent pas peuvent ne jamais être enregistrés. Il utilise la syntaxe libpcap, par exemple `tcp port 443 and host 192.168.1.10` [2]. Il est efficace pour réduire le volume, mais une erreur peut vous faire perdre un élément nécessaire à l’analyse.

Un **filtre d’affichage** est appliqué lors de la visualisation ou de l’analyse d’un fichier déjà capturé. Il utilise le langage de Wireshark, plus riche, et masque les paquets non correspondants sans modifier le fichier. Wireshark permet notamment de tester la présence d’un protocole ou d’un champ, de comparer des valeurs, d’utiliser des opérateurs logiques, des ensembles et des expressions régulières [1].

| Besoin | Filtre de capture | Filtre d’affichage |
|---|---|---|
| Capturer seulement TCP/443 | `tcp port 443` | `tcp.port == 443` |
| Hôte donné | `host 192.168.1.10` | `ip.addr == 192.168.1.10` |
| DNS | `udp port 53` | `dns` |
| Retransmissions TCP | Impossible de façon équivalente | `tcp.analysis.retransmission` |
| HTTP 4xx/5xx | Impossible de façon équivalente | `http.response.code >= 400` |
| Réduire le volume en direct | Excellent | Moins efficace en capture live |
| Explorer après coup | Non | Excellent |

## 7.2 Filtres de capture libpcap

Exemples :

```text
host 10.0.0.5
src host 10.0.0.5
dst net 192.168.1.0/24
tcp port 22
udp port 53
tcp and not port 22
ether host 00:11:22:33:44:55
icmp
broadcast or multicast
```

Les parenthèses sont utiles pour éviter les ambiguïtés :

```text
host 10.0.0.5 and (tcp port 80 or tcp port 443)
```

En capture live, évitez de filtrer trop tôt si vous ne connaissez pas encore la cause. Commencez par une capture courte, large et contrôlée, puis utilisez un filtre d’affichage. Pour un réseau volumineux, documentez précisément le filtre de capture, car il devient une limite méthodologique.

## 7.3 Filtres d’affichage Wireshark

Filtres de base :

```text
eth
arp
ip
ipv6
tcp
udp
dns
http
tls
icmp
```

Adresses et ports :

```text
ip.addr == 192.168.1.10
ip.src == 192.168.1.10
ip.dst == 192.168.1.10
ipv6.addr == 2001:db8::10
tcp.port == 443
udp.port == 53
```

Logique :

```text
ip.addr == 192.168.1.10 && tcp.port == 443
ip.addr == 192.168.1.10 || ip.addr == 192.168.1.11
!(arp || icmp)
http.request && ip.dst == 192.168.1.20
```

Présence et comparaisons :

```text
tcp.flags.syn == 1
tcp.flags.reset == 1
tcp.len > 0
frame.len > 1000
dns.qry.name
dns.qry.name contains "example"
http.request.method in {"GET", "POST"}
tcp.port in {22, 80, 443, 8080}
```

Régex et fonctions :

```text
http.host matches r"(^|\.)example\.org$"
lower(http.user_agent) contains "curl"
len(http.request.uri) > 100
count(ip.addr) > 2
```

Wireshark signale souvent si un champ est inconnu ou mal écrit. Utilisez l’autocomplétion et cliquez sur un champ dans les détails pour construire un filtre fiable. Les noms de champs et certains comportements peuvent changer selon la version ; évitez de copier un filtre ancien sans le tester.

## 7.4 Filtrer un flux TCP

Après avoir sélectionné un paquet TCP, utilisez **Analyze → Follow → TCP Stream**. Wireshark propose alors un filtre de la forme :

```text
tcp.stream == 7
```

Vous pouvez aussi partir d’un quadruplet :

```text
ip.addr == 10.0.0.10 && ip.addr == 10.0.0.20 && tcp.port == 443
```

Le filtre `ip.addr == A && ip.addr == B` signifie que les deux adresses apparaissent dans le paquet, indépendamment de la direction. Pour imposer une direction, utilisez `ip.src` et `ip.dst`.

---

# 8. Lire une trame couche par couche

Sélectionnez un paquet et développez chaque niveau dans le panneau de détails. Pour chaque champ, posez une question simple.

| Niveau | Champs à regarder | Questions |
|---|---|---|
| Frame | numéro, timestamp, longueur capturée, longueur originale | Le paquet a-t-il été tronqué ? Quand a-t-il été capturé ? |
| Ethernet | MAC source/destination, EtherType | Qui parle sur le segment local ? Broadcast ou unicast ? |
| VLAN | identifiant VLAN, priorité, EtherType interne | Le trafic appartient-il au bon segment ? |
| IP | source, destination, TTL, fragmentation, longueur | Le chemin logique est-il cohérent ? Le paquet est-il fragmenté ? |
| TCP/UDP | ports, flags, séquence, ACK, longueur | Le transport progresse-t-il ? Y a-t-il une réponse ? |
| Application | requête, réponse, code, identifiant | Le service répond-il correctement ? |
| Data | bytes, contenu, entropie apparente | Les données sont-elles lisibles, compressées ou chiffrées ? |

## 8.1 Longueur capturée contre longueur réelle

Un PCAP peut contenir un paquet partiellement capturé si le snaplen était insuffisant ou si la capture a été tronquée. Comparez `Captured Length` et `Frame Length`. Une analyse applicative peut être impossible si la partie utile n’a pas été enregistrée.

## 8.2 Checksum incorrect

Les cartes réseau et les systèmes modernes utilisent des mécanismes d’offloading : la pile peut calculer certains checksums après que le paquet a été remis au mécanisme de capture. Wireshark peut alors afficher un checksum incorrect alors que le paquet a été correctement transmis sur le réseau, ou l’inverse selon le point de capture. Ne transformez pas un checksum incorrect isolé en preuve d’attaque ou de corruption ; vérifiez la capture sur un autre point, les préférences de validation et les offloads de l’interface.

## 8.3 Reassembly et segmentation

Une réponse applicative peut être répartie sur plusieurs segments TCP. Activez ou vérifiez les options de réassemblage lorsque vous avez besoin de voir l’objet complet. Une grande requête peut également être découpée au niveau TCP ; le nombre de paquets ne correspond donc pas nécessairement au nombre de messages applicatifs.

---

# 9. Analyser les protocoles les plus importants

## 9.1 Analyse ARP : résolution locale

Méthode : filtrez `arp`, repérez la requête, trouvez la réponse et vérifiez si l’adresse MAC est cohérente avec la topologie attendue. Une requête répétée peut être normale lors d’une expiration de cache ou d’un changement réseau. Une adresse IPv4 revendiquée par plusieurs MAC mérite une investigation, mais il faut confirmer avec l’état réel des machines et des commutateurs.

## 9.2 Analyse DHCP : obtention de configuration

Filtrez `dhcp`, puis reconstituez la séquence Discover/Offer/Request/ACK. Examinez le serveur qui répond, les options DNS, la passerelle, le masque, le domaine et la durée du bail. Si le client diffuse des demandes sans recevoir d’ACK, examinez le VLAN, le relais DHCP, les ACL et la présence de réponses concurrentes.

## 9.3 Analyse DNS : délai, erreur et mauvais serveur

Filtrez `dns` et comparez les timestamps requête/réponse. Vérifiez le nom, le type, le serveur interrogé, le code de réponse et la présence de plusieurs tentatives. Recherchez des retransmissions UDP, une bascule vers TCP, des réponses SERVFAIL, REFUSED ou NXDOMAIN. Un délai DNS ne doit pas être confondu avec le délai de connexion au serveur final.

## 9.4 Analyse TCP : établir, transférer, fermer

Commencez par le handshake. Le résultat fournit plusieurs catégories :

| Observation | Interprétations possibles |
|---|---|
| SYN puis SYN/ACK puis ACK | Connexion établie normalement |
| SYN puis aucun retour | Perte, filtrage, route absente, serveur inaccessible ou capture incomplète |
| SYN puis RST/ACK | Port fermé, service refusé ou équipement qui rejette |
| SYN/ACK puis aucun ACK client | Réponse perdue, client inaccessible, routage asymétrique ou point de capture partiel |
| Données puis retransmissions | Perte, congestion, réordonnancement ou artefact de capture |
| Fenêtre nulle | Récepteur temporairement incapable d’absorber davantage de données |
| FIN dans les deux sens | Fermeture ordonnée |
| RST pendant les données | Fermeture abrupte ou erreur de session |

Ne regardez pas uniquement les couleurs de Wireshark. Ouvrez les champs d’analyse, comparez les directions et utilisez **Statistics → TCP Stream Graphs** pour étudier le débit, les séquences et les fenêtres.

## 9.5 Analyse HTTP

Pour une requête HTTP en clair, repérez la ligne de requête, l’hôte, l’URI, les en-têtes, la réponse et le code. Les codes `2xx`, `3xx`, `4xx` et `5xx` n’ont pas la même signification ; une réponse `404` prouve que le serveur a répondu « ressource non trouvée », alors qu’un timeout ne prouve aucune réponse applicative.

Utilisez **Follow HTTP Stream** lorsque disponible. Exportez des objets uniquement dans un environnement autorisé et rappelez-vous qu’un fichier récupéré depuis une capture peut être malveillant ; ne l’exécutez pas.

## 9.6 Analyse TLS

Examinez le `ClientHello`, le `ServerHello`, la version négociée, les extensions visibles, le nom de serveur indiqué lorsqu’il est présent, le certificat éventuel selon le protocole et les alertes. Dans TLS 1.3, de nombreux éléments sont chiffrés après les premières étapes [6].

Un certificat invalide côté client ne signifie pas forcément que le réseau a modifié le trafic : cela peut être un certificat expiré, un nom absent, une chaîne incomplète ou une horloge incorrecte. Corrélez l’analyse réseau avec les journaux de l’application et l’heure système.

## 9.7 Analyse IPv6 et ICMPv6

Filtrez `ipv6 || icmpv6`. Recherchez la découverte de voisins, les annonces de routeur, les erreurs de taille et les problèmes de `Hop Limit`. Un réseau IPv4 fonctionnel peut avoir un problème IPv6 qui provoque des délais de connexion ou des préférences de chemin inattendues.

---

# 10. Dépanner méthodiquement avec Wireshark

## 10.1 La matrice en quatre questions

Pour presque tout problème, répondez dans cet ordre :

1. **Le paquet quitte-t-il le client ?**
2. **Le paquet atteint-il le serveur ou le prochain saut ?**
3. **Le serveur répond-il au niveau transport ?**
4. **L’application répond-elle correctement et dans un délai acceptable ?**

Cette séparation évite de confondre un problème DNS, un problème TCP et une erreur HTTP.

## 10.2 Problème de connexion

Commencez par filtrer l’adresse ou le flux, puis inspectez les SYN. Si aucun SYN n’est présent, le problème peut être local à l’application, au DNS ou au choix d’interface. Si le SYN sort mais aucune réponse n’arrive au point de capture, élargissez l’analyse : route, pare-feu, serveur, NAT ou capture à sens unique. Si un RST revient, recherchez qui l’envoie et si le port est réellement à l’écoute.

## 10.3 Problème de lenteur

Une page lente est un symptôme, pas une cause. Séparez : résolution DNS, établissement TCP, handshake TLS, attente serveur, téléchargement et rendu côté navigateur. Mesurez les délais entre les événements correspondants et comparez plusieurs transactions similaires.

## 10.4 Problème de pertes ou retransmissions

Filtrez les champs d’analyse TCP, puis vérifiez les timestamps, les numéros de séquence, les ACK, le sens de la conversation et le point de capture. Une retransmission peut signifier que l’émetteur n’a pas reçu l’ACK, mais le paquet original peut avoir été perdu avant le point de capture ou l’ACK peut avoir été capturé sur un autre chemin.

## 10.5 Problème DNS

Comparez la requête et la réponse par identifiant et par nom. Vérifiez si la réponse revient d’un serveur autorisé, récursif ou intermédiaire, si elle comporte une erreur et si le client réessaie vers un autre serveur. Inspectez aussi les requêtes IPv4/IPv6 parallèles, car une résolution peut être correcte mais suivie d’un problème de connectivité.

## 10.6 Problème de débit

Utilisez les graphes I/O, les statistiques de conversation et les graphes TCP. Distinguez débit applicatif, débit TCP et débit sur le lien. Une fenêtre de réception faible, un RTT élevé, des retransmissions, une MTU inadéquate ou un traitement serveur lent peuvent produire des signatures différentes.

---

# 11. Statistiques, flux, graphiques et reconstruction

## 11.1 Menus Statistics et Analyze

Les fonctions les plus utiles sont :

| Fonction | Utilité |
|---|---|
| Endpoints | Lister les hôtes et ports observés |
| Conversations | Regrouper les échanges par paire et protocole |
| Protocol Hierarchy | Voir la composition globale de la capture |
| I/O Graphs | Visualiser paquets ou octets dans le temps |
| Flow Graph | Représenter l’ordre des messages entre endpoints |
| Expert Information | Regrouper des avertissements et erreurs de décodage |
| Resolved Addresses | Vérifier les résolutions de noms effectuées |
| Follow Stream | Reconstruire une conversation lisible |

## 11.2 Expert Information

La vue Expert peut signaler des retransmissions, des segments hors ordre, des problèmes de protocole et des alertes. Utilisez-la comme index de recherche. Chaque entrée doit être vérifiée dans le paquet réel et replacée dans son contexte. Une alerte « malformed » peut venir d’une capture tronquée, d’un dissector qui ne connaît pas une extension, d’un encapsulage inhabituel ou d’une donnée réellement invalide.

## 11.3 I/O Graphs

Un graphe permet de repérer un pic, une période silencieuse ou un changement de débit. Ajoutez des courbes séparées pour le trafic total, les retransmissions, le DNS ou un flux particulier. Utilisez des filtres identiques entre les courbes afin que la comparaison soit interprétable.

## 11.4 Export d’objets

Pour HTTP, SMB, DICOM et certains protocoles, Wireshark peut proposer l’export d’objets reconstruits. Cette fonction est utile en réponse à incident, mais elle produit des artefacts potentiellement sensibles ou dangereux. Exportez vers un dossier isolé, calculez les hashes et n’ouvrez pas les fichiers directement sur votre poste principal.

---

# 12. Wireshark en ligne de commande

## 12.1 Lister les interfaces

```bash
tshark -D
```

TShark peut capturer du trafic live ou lire une capture existante, et utilise la même famille de formats que Wireshark [7].

## 12.2 Capturer avec TShark

```bash
sudo tshark -i 2 -a duration:30 -w capture.pcapng
sudo tshark -i 2 -f "host 192.168.1.10 and (tcp port 80 or tcp port 443)" -a duration:20 -w web.pcapng
```

Le paramètre `-f` désigne un filtre de capture. Pour un fichier existant, `-Y` désigne un filtre d’affichage :

```bash
tshark -r capture.pcapng -Y 'dns'
tshark -r capture.pcapng -Y 'tcp.analysis.retransmission'
tshark -r capture.pcapng -Y 'http.response.code >= 400'
```

La documentation TShark rappelle que les filtres de capture sont généralement plus efficaces que les filtres d’affichage lors d’une capture live [7].

## 12.3 Extraire des champs

```bash
tshark -r capture.pcapng -Y 'dns.qry.name' \
  -T fields -e frame.number -e frame.time_relative \
  -e ip.src -e ip.dst -e dns.qry.name
```

Pour du CSV exploitable :

```bash
tshark -r capture.pcapng -Y 'http.request' \
  -T fields -E header=y -E separator=, -E quote=d \
  -e frame.time -e ip.src -e ip.dst \
  -e http.request.method -e http.host -e http.request.uri \
  > requetes_http.csv
```

Pour détailler TCP et IP :

```bash
tshark -r capture.pcapng -Y 'tcp.stream == 0' -O tcp,ip
```

Un fichier de sortie texte ne doit pas être confondu avec une capture binaire. `-w` écrit les paquets ; `-T fields` écrit des champs décodés.

## 12.4 Statistiques TShark

```bash
tshark -r capture.pcapng -q -z io,stat,1
tshark -r capture.pcapng -q -z conv,tcp
tshark -r capture.pcapng -q -z endpoints,ip
```

Les options statistiques disponibles peuvent varier selon la version. Utilisez `tshark -h` et `tshark -z help` pour vérifier la syntaxe locale.

## 12.5 Capinfos et Editcap

`capinfos` résume un ou plusieurs fichiers de capture et peut produire un format tabulaire pour une importation dans un tableur [8] :

```bash
capinfos capture.pcapng
capinfos -T -m -Q capture.pcapng > capture.csv
```

`editcap` extrait, découpe, convertit ou déduplique des captures [9] :

```bash
editcap -r capture.pcapng extrait.pcapng 100-500
editcap -A '2026-08-13 10:00:00' -B '2026-08-13 10:05:00' \
  capture.pcapng fenetre.pcapng
editcap -d capture.pcapng sans_doublons.pcapng
```

Conservez toujours l’original. Toute opération de découpage ou déduplication doit être notée dans le rapport.

---

# 13. Limites réelles de l’observation

## 13.1 Le chiffrement

TLS protège le contenu contre l’écoute passive ; vous pourrez souvent analyser le timing, les endpoints, les tailles, la version négociée et les alertes, mais pas lire le contenu sans secrets autorisés [6]. SSH, VPN, QUIC et DNS chiffré ont également des limites spécifiques.

## 13.2 Offloading et faux checksums

Checksum offload, segmentation offload et réception agrégée peuvent modifier l’apparence d’un paquet sur l’hôte qui capture. Un checksum marqué incorrect peut être un artefact local. Lorsque le diagnostic est important, capturez sur un autre point ou désactivez temporairement certains offloads dans un laboratoire contrôlé, puis documentez le changement.

## 13.3 Promiscuous mode et réseau commuté

Le mode promiscuous permet à une interface de remettre davantage de trames au système, mais il ne force pas un switch à envoyer tout le trafic sur ce port. Pour observer plusieurs machines, utilisez un port miroir/SPAN, un TAP, une capture sur l’hôte concerné ou une sonde adaptée.

## 13.4 Wi-Fi

Le Wi-Fi ajoute les subtilités 802.11, Radiotap, canaux, contrôle, management, chiffrement et mode monitor. Le mode monitor peut désassocier l’adaptateur du réseau et n’est pas supporté de la même manière sur tous les systèmes [10]. Une capture Wi-Fi réalisée sur l’hôte connecté ne donne pas nécessairement toutes les trames radio visibles par un véritable capteur en mode monitor.

## 13.5 Timestamps et captures multipoints

Deux captures faites sur deux machines peuvent avoir des horloges différentes. Avant de comparer les délais, synchronisez les horloges ou estimez le décalage. Les paquets peuvent aussi apparaître dans un ordre différent selon les buffers et les interfaces. Utilisez `capinfos` pour vérifier si les timestamps sont strictement chronologiques, et `editcap` uniquement après avoir compris l’impact de toute correction [8] [9].

## 13.6 Asymétrie du chemin

Vous pouvez capturer les requêtes sans les réponses, ou les réponses sans les requêtes. Cette asymétrie peut venir du routage, d’un port miroir incomplet, d’un tunnel ou d’une interface mal choisie. Une absence dans un PCAP est une absence d’observation, pas toujours une absence sur le réseau.

---

# 14. Travaux pratiques progressifs

Les exercices suivants doivent être exécutés uniquement sur votre machine, un laboratoire ou un PCAP explicitement autorisé. Chaque exercice comprend un objectif, une préparation, une méthode d’analyse et des questions de validation.

## TP1 — Identifier les interfaces et capturer du trafic local

**Objectif.** Savoir quelle interface transporte le trafic et produire un premier PCAP documenté.

Lancez `ip -br addr`, `tshark -D`, puis capturez vingt secondes sur l’interface active. Pendant la capture, exécutez `ping -c 3 1.1.1.1` ou une cible de laboratoire autorisée. Ouvrez le fichier et filtrez `icmp`.

**Questions.** Quelle est l’adresse MAC source ? Quelle adresse IP est utilisée ? Quel est le TTL ou Hop Limit ? Les Echo Request et Echo Reply sont-ils visibles dans les deux sens ?

**Validation.** Vous devez pouvoir expliquer la différence entre la trame Ethernet, le paquet IP et le message ICMP.

## TP2 — Observer ARP et la passerelle

**Objectif.** Comprendre la résolution locale.

Videz ou observez le cache ARP uniquement sur votre propre machine, puis déclenchez une connexion vers une adresse de votre réseau local. Utilisez :

```bash
ip neigh
sudo ip neigh flush all
ping -c 1 192.168.1.1
```

Adaptez l’adresse de passerelle à votre environnement. Filtrez `arp` et observez la requête ainsi que la réponse.

**Questions.** Quelle IPv4 est recherchée ? Quelle MAC répond ? La destination Ethernet est-elle la même que la destination IP ?

## TP3 — DNS : requête, réponse et délai

**Objectif.** Mesurer une résolution DNS.

Lancez :

```bash
dig example.org
```

Capturez le trafic et filtrez `dns`. Cliquez sur la requête, puis repérez la réponse associée. Utilisez `dns.time` si le dissector le fournit dans votre version.

**Questions.** Quel serveur DNS répond ? Quel est le type de requête ? Le code de réponse indique-t-il un succès ? Y a-t-il plusieurs tentatives ?

## TP4 — DHCP en laboratoire

**Objectif.** Reconstruire une attribution d’adresse.

Réalisez cet exercice sur une VM ou un réseau dont vous contrôlez le DHCP. Filtrez `dhcp` et observez une séquence complète. Ne renouvelez pas un bail sur un réseau de production sans savoir quelles conséquences cela peut avoir.

**Questions.** Quel client demande une adresse ? Quel serveur répond ? Quelles options indiquent la passerelle et le DNS ? Le paquet est-il broadcast ou unicast ?

## TP5 — Handshake TCP et port fermé

**Objectif.** Distinguer connexion établie et refus.

Sur votre propre machine, démarrez un service de test ou utilisez un service connu. Capturez une tentative vers un port ouvert puis une tentative vers un port fermé. Filtrez :

```text
tcp.flags.syn == 1 || tcp.flags.reset == 1
```

**Questions.** Dans quel cas observez-vous SYN/SYN-ACK/ACK ? Dans quel cas voyez-vous RST ? Qui envoie le RST ?

## TP6 — HTTP en clair dans un laboratoire

**Objectif.** Suivre une requête et une réponse.

Utilisez un serveur local de test :

```bash
python3 -m http.server 8000 --directory /tmp
curl -v http://127.0.0.1:8000/
```

Capturez sur `lo`, filtrez `http` ou `tcp.port == 8000`, puis utilisez **Follow TCP Stream**. Ne transmettez jamais de véritables mots de passe dans ce laboratoire.

**Questions.** Quelle méthode HTTP est utilisée ? Quelle URI est demandée ? Quel code de réponse est renvoyé ? Quel est le délai entre la requête et la réponse ?

## TP7 — Retransmission TCP contrôlée avec PCAP fourni

**Objectif.** Reconnaître une retransmission sans conclure trop vite.

Utilisez un PCAP pédagogique public ou une capture générée en laboratoire. Filtrez :

```text
tcp.analysis.retransmission || tcp.analysis.fast_retransmission
```

Sélectionnez une retransmission, repérez le segment original supposé, comparez les numéros de séquence et observez la réponse ACK.

**Questions.** La retransmission est-elle confirmée par un ACK dupliqué ? Le paquet original est-il visible ? Le point de capture permet-il de voir les deux directions ?

## TP8 — TLS et limites de visibilité

**Objectif.** Comprendre ce qui reste observable sous chiffrement.

Exécutez une connexion HTTPS vers un service de test autorisé et filtrez `tls`. Observez le `ClientHello`, le `ServerHello`, les versions et extensions visibles, puis les données chiffrées.

**Questions.** Pouvez-vous lire l’URI complète ? Pouvez-vous voir les tailles et le timing ? Quelles informations peuvent être déduites sans prétendre lire le contenu ?

## TP9 — Automatiser une extraction avec TShark

**Objectif.** Produire un tableau exploitable.

À partir d’un PCAP contenant du DNS :

```bash
tshark -r capture.pcapng -Y 'dns.qry.name' \
  -T fields -E header=y -E separator=';' \
  -e frame.time_relative -e ip.src -e ip.dst -e dns.qry.name \
  > dns.csv
```

Ouvrez le fichier dans un tableur ou analysez-le avec Python/pandas. Vérifiez toujours que les champs vides signifient réellement « absent » et non « non décodé ».

## TP10 — Mini-enquête chronométrée

**Objectif.** Produire un diagnostic structuré.

Prenez une capture contenant une transaction applicative lente. Répondez dans un rapport d’une page : quel client, quel serveur, quel protocole, quel flux, quels numéros de paquets, quels délais, quelle hypothèse, quelles limites et quelle action de vérification.

Le rapport doit contenir au moins un filtre exact, un tableau de mesures et une conclusion qui ne dépasse pas ce que la capture démontre.

---

# 15. Méthode orientée CTF et défense

Dans un CTF légal, la rapidité vient d’une bonne réduction de l’espace de recherche. Commencez par `capinfos`, puis `Statistics → Protocol Hierarchy`, `Endpoints` et `Conversations`. Cherchez ensuite les protocoles inattendus, les flux longs, les ports inhabituels, les fragments, les DNS rares, les données encodées et les erreurs de décodage.

Pour une analyse de fichier suspect, ne vous contentez pas de rechercher une chaîne visible. Vérifiez les flux TCP/UDP, le sens des échanges, les noms DNS, les URI, les pièces jointes, les blobs encodés, les tailles et les timestamps. Des données peuvent être réparties sur plusieurs paquets, compressées, chiffrées ou transportées dans un protocole détourné.

Filtres de triage utiles :

```text
http.request || dns.qry.name || tls.handshake
tcp.analysis.flags
frame contains "flag"
frame contains "token"
data.data contains 66:6c:61:67
udp && frame.len > 1000
ip.addr == 10.10.10.0/24
```

Pour la défense, ne marquez pas automatiquement comme malveillant un port non standard, un paquet DNS long ou un user-agent rare. Cherchez une combinaison d’indices : fréquence, destination, récurrence, absence de réponse, anomalie temporelle, écart avec la baseline et corrélation avec les logs système.

Une bonne investigation documente aussi les éléments négatifs : « aucun contenu HTTP en clair observé », « aucune réponse DNS associée dans le périmètre capturé », « aucun paquet IPv6 dans cette interface ». Cela empêche de transformer une visibilité partielle en certitude.

---

# 16. Programme d’entraînement sur trente jours

| Période | Travail principal | Résultat attendu |
|---|---|---|
| Jours 1–3 | OSI/TCP-IP, MAC, IPv4, CIDR, ports | Dessiner l’encapsulation d’une requête |
| Jours 4–6 | Wireshark, interfaces, captures, PCAPNG | Capturer et documenter un PCAP court |
| Jours 7–9 | Filtres de capture et d’affichage | Écrire dix filtres sans confusion de syntaxe |
| Jours 10–12 | ARP, ICMP, IPv6/ICMPv6 | Expliquer un problème local et un problème de chemin |
| Jours 13–16 | TCP, handshake, flags, séquences | Distinguer refus, timeout et retransmission |
| Jours 17–19 | UDP, DNS, DHCP | Mesurer résolution et attribution d’adresse |
| Jours 20–22 | HTTP, TLS, flux et réassemblage | Suivre une transaction et ses limites de visibilité |
| Jours 23–25 | Statistiques, graphes, TShark | Produire un CSV et un graphe d’activité |
| Jours 26–28 | PCAP de dépannage ou CTF légal | Résoudre une enquête complète |
| Jours 29–30 | Rapport et révision | Livrer un diagnostic avec preuves et limites |

Chaque jour, choisissez une capture, formulez trois hypothèses, écrivez trois filtres, vérifiez les paquets et rédigez cinq lignes de conclusion. La progression est meilleure avec de petites captures comprises en profondeur qu’avec des fichiers énormes seulement parcourus superficiellement.

---

# 17. Fiche mémo finale

## Commandes Linux

```bash
ip -br addr
ip route
ip neigh
ss -tulpen
dig example.org
curl -v https://example.org
tshark -D
capinfos capture.pcapng
```

## Capture courte

```bash
sudo dumpcap -i 2 -a duration:30 -w capture.pcapng
```

## Filtres de capture

```text
host 192.168.1.10
tcp port 443
udp port 53
icmp
host 192.168.1.10 and (tcp port 80 or tcp port 443)
```

## Filtres d’affichage

```text
ip.addr == 192.168.1.10
tcp.port == 443
dns
dns.flags.response == 0
http.request
http.response.code >= 400
tls.handshake
tcp.analysis.retransmission
tcp.flags.reset == 1
icmp || icmpv6
```

## Diagnostic TCP express

```text
# SYN sans ACK initial
tcp.flags.syn == 1 && tcp.flags.ack == 0

# Réinitialisations
tcp.flags.reset == 1

# Retransmissions et pertes signalées
tcp.analysis.retransmission || tcp.analysis.lost_segment

# Fenêtre nulle
tcp.analysis.zero_window
```

## Extraction TShark

```bash
tshark -r capture.pcapng -Y 'dns' -T fields \
  -e frame.number -e ip.src -e ip.dst -e dns.qry.name
```

## Les cinq erreurs à éviter

Ne confondez jamais filtre de capture et filtre d’affichage. Ne concluez pas à une perte réseau à partir d’un seul indicateur. Ne prenez pas un checksum incorrect local pour une preuve de corruption. Ne supposez pas que le mode promiscuous montre tout le trafic d’un switch. Enfin, ne cherchez pas à déchiffrer ou intercepter des communications qui ne vous appartiennent pas.

> **Principe final :** un analyste réseau compétent ne se contente pas de trouver un paquet intéressant ; il démontre pourquoi ce paquet répond à la question, ce qu’il permet de conclure et ce qu’il ne permet pas de conclure.

---

# 18. Références

[1]: https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html "Wireshark User’s Guide — Building Display Filter Expressions"

[2]: https://www.wireshark.org/docs/wsug_html_chunked/ChCapCaptureFilterSection.html "Wireshark User’s Guide — Filtering while capturing"

[3]: https://www.rfc-editor.org/rfc/rfc8200 "RFC 8200 — Internet Protocol, Version 6 (IPv6) Specification"

[4]: https://www.rfc-editor.org/rfc/rfc9293 "RFC 9293 — Transmission Control Protocol (TCP)"

[5]: https://www.rfc-editor.org/rfc/rfc768 "RFC 768 — User Datagram Protocol"

[6]: https://www.rfc-editor.org/rfc/rfc8446 "RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3"

[7]: https://www.wireshark.org/docs/man-pages/tshark.html "Wireshark TShark Manual Page"

[8]: https://www.wireshark.org/docs/man-pages/capinfos.html "Wireshark Capinfos Manual Page"

[9]: https://www.wireshark.org/docs/man-pages/editcap.html "Wireshark Editcap Manual Page"

[10]: https://www.wireshark.org/docs/man-pages/dumpcap.html "Wireshark Dumpcap Manual Page"

*Document pédagogique produit le 13 août 2026. Les noms de champs et options peuvent varier légèrement selon la version de Wireshark ; vérifiez toujours la documentation correspondant à votre installation.*

---

## Annexe — modèle de rapport d’analyse

**Contexte.** Décrire la machine, l’interface, la période de capture et l’objectif.  
**Fichier.** Nom, format, taille, hash SHA-256, durée et nombre de paquets.  
**Méthode.** Filtres appliqués, statistiques consultées et éventuels traitements.  
**Observation principale.** Décrire les paquets avec numéros, endpoints, timestamps et champs pertinents.  
**Hypothèse.** Expliquer le mécanisme réseau susceptible de produire le symptôme.  
**Limites.** Mentionner chiffrement, capture partielle, asymétrie, offloading, timestamps ou champs absents.  
**Conclusion.** Répondre directement à la question sans dépasser les preuves.  
**Vérification recommandée.** Proposer un test autorisé : capture sur un autre point, comparaison avec les logs, test DNS, vérification du service ou reproduction dans un laboratoire.

| Mesure | Valeur | Paquet(s) | Interprétation |
|---|---:|---|---|
| Délai DNS | à compléter | requête/réponse | résolution lente ou normale |
| Délai TCP | à compléter | SYN/SYN-ACK | établissement de connexion |
| Délai applicatif | à compléter | requête/réponse | traitement serveur ou transfert |
| Retransmissions | à compléter | flux concerné | indice à corréler |
| Volume | à compléter | conversation | activité observée |

Ce modèle transforme une exploration Wireshark en analyse vérifiable et réutilisable.
