# LAB – Détection d’activités réseau suspectes dans les logs Linux

## Objectifs pédagogiques

* Lire un fichier de logs système ou firewall.
* Écrire un script Python pour :

  * Identifier des scans de ports (SYN flood, Nmap, etc.).
  * Détecter des pics d’activité réseau suspects.
  * Extraire des IPs externes suspectes.

---

## Contexte

Vous êtes analyste sécurité. Le serveur vous transmet ses logs réseau. Votre mission est d'écrire un script Python qui **analyse les logs du pare-feu** (`/var/log/syslog` ou `/var/log/ufw.log`) pour repérer :

* des connexions entrantes inhabituelles,
* des répétitions rapides (plusieurs connexions en moins d’1 seconde),
* des ports scannés dans un court intervalle,
* des IPs qui devraient être bannies.

---

## Étapes du TP

### 1. Simuler ou récupérer un fichier `/var/log/ufw.log`

Activez UFW sur un serveur :

```bash
sudo ufw enable
sudo ufw logging on
```

Simulez du trafic avec Nmap ou `curl` :

```bash
nmap -p 20-80 <IP_du_serveur>
```

Le fichier `/var/log/ufw.log` sera généré.

---

### 2. Exemple de lignes de log UFW

```
Jun 30 12:10:22 server kernel: [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=192.168.1.22 DST=192.168.1.10 LEN=60 ...
Jun 30 12:10:23 server kernel: [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=10.10.10.1 DST=192.168.1.10 LEN=60 ...
```

---

### 3. Script Python : `firewall_analyzer.py`

```python
import re
from collections import defaultdict

log_file = "ufw.log"
ip_hits = defaultdict(int)
ports_accessed = defaultdict(set)

with open(log_file, "r", encoding="utf-8") as f:
    for line in f:
        match = re.search(r'SRC=([\d.]+).*DPT=(\d+)', line)
        if match:
            ip, port = match.groups()
            ip_hits[ip] += 1
            ports_accessed[ip].add(port)

# Afficher les IPs ayant généré le plus de requêtes
print("\n🔍 Rapport des IPs suspectes :")
for ip, count in sorted(ip_hits.items(), key=lambda x: x[1], reverse=True):
    print(f"{ip} - {count} requêtes sur ports {', '.join(sorted(ports_accessed[ip]))}")
```

---

## Résultat attendu

Le script affiche une **liste d’IP suspectes** classées par nombre de tentatives + ports touchés :

```
192.168.1.22 - 15 requêtes sur ports 22, 80, 443
10.10.10.1 - 8 requêtes sur ports 22
```

---
