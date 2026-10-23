# fqdnscan

<img width="1243" height="898" alt="image" src="https://github.com/user-attachments/assets/75ce83dc-b524-4a98-84fc-3800e6c4b91a" />

Script interactif qui part d'une liste de domaines, cherche des sous-domaines, résout les enregistrements DNS et peut sonder les sites HTTP. Les résultats sortent en CSV et en JSON.

Le déroulement est décrit dans [SCHEMA.md](SCHEMA.md).

À n'utiliser que sur des domaines qui vous appartiennent, ou pour lesquels vous avez l'autorisation de faire ces requêtes.

## Prérequis

- Python 3.10 ou plus récent
- `dig` (paquet `dnsutils` ou `bind-utils`)
- en option : [subfinder](https://github.com/projectdiscovery/subfinder) et [httpx](https://github.com/projectdiscovery/httpx)

Sans subfinder, la case correspondante ne trouve rien. Sans httpx, la sonde web ne trouve rien. crt.sh et dig suffisent pour un premier passage.

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Utilisation

```bash
python3 fqdnscan.py exemple.txt
```

Sans argument, le script demande le chemin du fichier.

Le fichier contient un domaine par ligne. Les lignes vides et les commentaires (`#`) sont ignorés. Un exemple est fourni dans `exemple.txt`.

Le menu propose :

1. les sources de sous-domaines (subfinder, crt.sh) ;
2. les types DNS (`A`, `AAAA`, `CNAME`, `MX`, `NS`, `SOA`, `TXT`) ;
3. la sonde HTTP.

Les exports sont écrits dans `results/` :

```text
results/recon_AAAAMMJJ_HHMMSS.csv
results/recon_AAAAMMJJ_HHMMSS.json
```

Le tableau du terminal s'arrête à 20 lignes. Les fichiers contiennent la totalité.

## Limites

- Un joker DNS est signalé, pas filtré. Si le domaine répond à n'importe quel nom, les adresses A qui suivent peuvent toutes être celle du joker.
- crt.sh et subfinder échouent en silence (outil absent, délai dépassé, JSON illisible). La résolution DNS continue avec les noms déjà connus.
- La sonde httpx s'arrête au bout de 120 secondes pour l'ensemble de la liste.
- Beaucoup de types DNS cochés sur beaucoup de noms produisent un appel `dig` par couple. Ça peut être long.
