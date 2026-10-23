#!/usr/bin/env python3
"""fqdnscan — reconnaissance de noms de domaine à partir d'un fichier de cibles.

Le programme charge des domaines, cherche des sous-domaines, interroge le DNS,
peut sonder le HTTP, puis écrit un CSV et un JSON. Le détail du flux est dans
SCHEMA.md.
"""

import csv
import json
import os
import subprocess
import sys
import tempfile
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

try:
    import requests
    import questionary
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
    from rich.table import Table
except ImportError:
    print("Erreur : requests, rich et questionary sont requis.")
    print("Installez-les avec : pip install -r requirements.txt")
    sys.exit(1)

console = Console()


def maintenant_utc() -> str:
    """Horodatage ISO 8601 en UTC, avec le suffixe Z."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def appartient_au_domaine(nom: str, domaine: str) -> bool:
    """Vrai si nom est le domaine, ou un sous-domaine de celui-ci.

    On ne se contente pas de endswith : « pasexemple.com » se terminerait
    par « exemple.com » sans en être un sous-domaine. Le point obligatoire
    devant le domaine évite ce faux positif.
    """
    nom = nom.strip().lower().rstrip(".")
    domaine = domaine.strip().lower().rstrip(".")
    if not nom or not domaine:
        return False
    return nom == domaine or nom.endswith("." + domaine)


def demander(question):
    """Pose une question interactive. Ctrl+C dans le menu arrête le programme."""
    reponse = question.ask()
    if reponse is None:
        console.print("\n[red]Saisie annulée.[/red]")
        sys.exit(0)
    return reponse


# ============================================================
# 1. Données et lecture du fichier de cibles
# ============================================================

@dataclass
class Actif:
    """Une ligne de résultat : un enregistrement DNS, ou une réponse HTTP."""

    domain: str
    fqdn: str
    source: str
    # Résolution DNS (dig)
    dns_type: Optional[str] = None
    name: Optional[str] = None
    ttl: Optional[int] = None
    dns_class: Optional[str] = None
    value: Optional[str] = None
    status: Optional[str] = None
    # Sonde HTTP (httpx)
    http_url: Optional[str] = None
    http_status: Optional[int] = None
    http_title: Optional[str] = None
    http_server: Optional[str] = None
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = maintenant_utc()


def charger_cibles(chemin: str) -> List[str]:
    """Lit un domaine par ligne. Ignore le vide et les lignes qui commencent par #."""
    cibles = []
    try:
        with open(chemin, "r", encoding="utf-8") as fichier:
            for ligne in fichier:
                ligne = ligne.strip()
                if ligne and not ligne.startswith("#"):
                    cibles.append(ligne.lower().rstrip("."))
    except OSError as erreur:
        console.print(f"[red]Lecture impossible : {erreur}[/red]")
        sys.exit(1)
    # dict.fromkeys garde l'ordre et retire les doublons.
    return list(dict.fromkeys(cibles))


# ============================================================
# 2. Recherche de sous-domaines
# ============================================================

class EnumerateurCrtsh:
    """Interroge les journaux de certificats publics via crt.sh."""

    @staticmethod
    def executer(domaine: str) -> Set[str]:
        trouves = set()
        try:
            url = f"https://crt.sh/?q=%.{domaine}&output=json"
            reponse = requests.get(url, timeout=20)
            if reponse.status_code != 200:
                return trouves
            for entree in reponse.json():
                # Un certificat peut lister plusieurs noms, un par ligne.
                for morceau in entree.get("name_value", "").splitlines():
                    morceau = morceau.strip().lower().rstrip(".")
                    if not morceau or "*" in morceau:
                        continue
                    if appartient_au_domaine(morceau, domaine):
                        trouves.add(morceau)
        except (requests.RequestException, ValueError):
            # Réseau coupé ou JSON illisible : on continue avec les autres sources.
            pass
        return trouves


class EnumerateurSubfinder:
    """Lance l'outil externe subfinder, s'il est installé."""

    @staticmethod
    def executer(domaine: str) -> Set[str]:
        trouves = set()
        try:
            processus = subprocess.run(
                ["subfinder", "-d", domaine, "-silent"],
                capture_output=True,
                text=True,
                timeout=60,
            )
            for ligne in processus.stdout.splitlines():
                nom = ligne.strip().lower().rstrip(".")
                if appartient_au_domaine(nom, domaine):
                    trouves.add(nom)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return trouves


# ============================================================
# 3. Résolution DNS
# ============================================================

class MoteurDns:
    """Appelle dig pour détecter un wildcard et lire les enregistrements."""

    def __init__(self, timeout: int = 5):
        self.timeout = timeout

    def detecter_wildcard(self, domaine: str) -> bool:
        """Vrai si un nom au hasard répond quand même.

        Le résultat est seulement affiché. Les noms découverts sont quand
        même résolus ensuite : un wildcard ne les retire pas de la liste.
        """
        nom_aleatoire = f"{uuid.uuid4().hex[:8]}.{domaine}"
        try:
            processus = subprocess.run(
                ["dig", "+short", nom_aleatoire, "A"],
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            return bool(processus.stdout.strip())
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False

    def resoudre(
        self, fqdn: str, type_enregistrement: str, source: str, domaine_racine: str
    ) -> List[Actif]:
        """Une requête dig. Sans réponse exploitable, on garde une ligne de statut."""
        commande = [
            "dig",
            "+noall",
            "+answer",
            "+comments",
            f"+time={self.timeout}",
            "+tries=1",
            fqdn,
            type_enregistrement,
        ]
        try:
            processus = subprocess.run(
                commande,
                capture_output=True,
                text=True,
                timeout=self.timeout + 2,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return [
                Actif(
                    domain=domaine_racine,
                    fqdn=fqdn,
                    source=source,
                    dns_type=type_enregistrement,
                    status="ERROR",
                )
            ]

        sortie = processus.stdout + processus.stderr
        statut = self._lire_statut(sortie)
        actifs = self._lire_reponses(sortie, fqdn, type_enregistrement, source, domaine_racine, statut)
        if actifs:
            return actifs
        return [
            Actif(
                domain=domaine_racine,
                fqdn=fqdn,
                source=source,
                dns_type=type_enregistrement,
                status=statut,
            )
        ]

    @staticmethod
    def _lire_statut(sortie: str) -> str:
        """Extrait NOERROR, NXDOMAIN, etc. de l'en-tête dig."""
        for ligne in sortie.splitlines():
            if "status:" not in ligne:
                continue
            try:
                return ligne.split("status:", 1)[1].split(",", 1)[0].strip()
            except IndexError:
                return "UNKNOWN"
        return "UNKNOWN"

    @staticmethod
    def _lire_reponses(
        sortie: str,
        fqdn: str,
        type_enregistrement: str,
        source: str,
        domaine_racine: str,
        statut: str,
    ) -> List[Actif]:
        """Parse la section ANSWER. Le format dig est : nom ttl classe type valeur."""
        actifs = []
        dans_reponse = False
        for ligne in sortie.splitlines():
            ligne = ligne.strip()
            if ligne.startswith(";; ANSWER SECTION:"):
                dans_reponse = True
                continue
            if ligne.startswith(";;") and dans_reponse:
                break
            if not dans_reponse or not ligne or ligne.startswith(";"):
                continue

            morceaux = ligne.split()
            if len(morceaux) >= 5 and morceaux[3] == type_enregistrement:
                actifs.append(
                    Actif(
                        domain=domaine_racine,
                        fqdn=fqdn,
                        source=source,
                        name=morceaux[0],
                        ttl=int(morceaux[1]) if morceaux[1].isdigit() else None,
                        dns_class=morceaux[2],
                        dns_type=morceaux[3],
                        value=" ".join(morceaux[4:]),
                        status=statut,
                    )
                )
        return actifs


# ============================================================
# 4. Sonde HTTP
# ============================================================

class MoteurHttpx:
    """Passe la liste des FQDN à httpx et récupère une ligne JSON par service."""

    @staticmethod
    def executer(infos_fqdn: Dict[str, dict]) -> List[Actif]:
        actifs = []
        fqdns = list(infos_fqdn.keys())
        if not fqdns:
            return actifs

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as fichier_temp:
            fichier_temp.write("\n".join(fqdns))
            chemin_temp = fichier_temp.name

        try:
            processus = subprocess.run(
                [
                    "httpx",
                    "-l",
                    chemin_temp,
                    "-silent",
                    "-json",
                    "-title",
                    "-tech-detect",
                    "-status-code",
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
            for ligne in processus.stdout.splitlines():
                actif = MoteurHttpx._ligne_vers_actif(ligne, infos_fqdn)
                if actif is not None:
                    actifs.append(actif)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
        finally:
            if os.path.exists(chemin_temp):
                os.remove(chemin_temp)
        return actifs

    @staticmethod
    def _ligne_vers_actif(ligne: str, infos_fqdn: Dict[str, dict]) -> Optional[Actif]:
        try:
            donnees = json.loads(ligne)
        except json.JSONDecodeError:
            return None

        fqdn = donnees.get("input", "")
        racine = infos_fqdn.get(fqdn, {}).get("root", fqdn)
        serveur = donnees.get("webserver", "")
        if not serveur and "tech" in donnees:
            serveur = ", ".join(donnees["tech"])[:50]

        return Actif(
            domain=racine,
            fqdn=fqdn,
            source="httpx",
            http_url=donnees.get("url", ""),
            http_status=donnees.get("status_code"),
            http_title=donnees.get("title", ""),
            http_server=serveur,
        )


# ============================================================
# 5. Enchaînement
# ============================================================

def exporter(actifs: List[Actif], dossier: str = "results"):
    """Écrit le même jeu de résultats en CSV et en JSON. Le nom porte la date."""
    os.makedirs(dossier, exist_ok=True)
    horodatage = datetime.now().strftime("%Y%m%d_%H%M%S")

    champs = list(Actif.__dataclass_fields__.keys())
    chemin_csv = os.path.join(dossier, f"recon_{horodatage}.csv")
    with open(chemin_csv, "w", newline="", encoding="utf-8") as fichier:
        ecrivain = csv.DictWriter(fichier, fieldnames=champs)
        ecrivain.writeheader()
        for actif in actifs:
            ecrivain.writerow(asdict(actif))

    chemin_json = os.path.join(dossier, f"recon_{horodatage}.json")
    with open(chemin_json, "w", encoding="utf-8") as fichier:
        json.dump([asdict(actif) for actif in actifs], fichier, indent=4, ensure_ascii=False)

    return chemin_csv, chemin_json


def choisir_fichier() -> str:
    """Argument positionnel, sinon un sélecteur de chemin."""
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        return sys.argv[1]
    return demander(questionary.path("Fichier texte (FQDN ou domaines) :"))


def collecter_sous_domaines(domaines, sources, infos_fqdn, progression):
    """Ajoute à infos_fqdn les noms trouvés, sans écraser une source déjà connue."""
    outils = [
        ("Subfinder", "Subfinder", EnumerateurSubfinder.executer),
        ("crt.sh (CT Logs)", "crt.sh", EnumerateurCrtsh.executer),
    ]
    for libelle, source, fonction in outils:
        if libelle not in sources:
            continue
        tache = progression.add_task(f"[cyan]{source}...", total=len(domaines))
        for domaine in domaines:
            for sous_domaine in fonction(domaine):
                if sous_domaine not in infos_fqdn:
                    infos_fqdn[sous_domaine] = {"source": source, "root": domaine}
            progression.advance(tache)
        progression.update(tache, description=f"[cyan]{source} (terminé)")


def main():
    console.print(
        Panel.fit(
            "[bold blue]fqdnscan[/bold blue]\n[dim]Sous-domaines, DNS et HTTP[/dim]",
            border_style="blue",
        )
    )

    chemin = choisir_fichier()
    if not chemin or not os.path.isfile(chemin):
        console.print("[red]Fichier introuvable.[/red]")
        sys.exit(1)

    domaines = charger_cibles(chemin)
    if not domaines:
        console.print(f"[red]Aucune cible dans {chemin}.[/red]")
        sys.exit(1)

    console.print(f"[green]{len(domaines)} cible(s) chargée(s).[/green]\n")

    sources = demander(
        questionary.checkbox(
            "Sources d'énumération :",
            choices=[
                questionary.Choice("Subfinder", checked=True),
                questionary.Choice("crt.sh (CT Logs)", checked=True),
            ],
        )
    )
    types_dns = demander(
        questionary.checkbox(
            "Types DNS à résoudre :",
            choices=[
                questionary.Choice("A", checked=True),
                questionary.Choice("AAAA", checked=True),
                questionary.Choice("CNAME", checked=True),
                questionary.Choice("MX", checked=True),
                questionary.Choice("NS", checked=True),
                questionary.Choice("SOA", checked=True),
                questionary.Choice("TXT", checked=True),
            ],
        )
    )
    modules = demander(
        questionary.checkbox(
            "Modules complémentaires :",
            choices=[
                questionary.Choice("httpx (Découverte Web HTTP/HTTPS)", checked=True),
            ],
        )
    )

    if not sources and not types_dns and not modules:
        console.print("[yellow]Aucune option cochée. Rien à faire.[/yellow]")
        sys.exit(0)

    # Chaque FQDN pointe vers son domaine d'origine et la source qui l'a trouvé.
    infos_fqdn = {domaine: {"source": "fichier", "root": domaine} for domaine in domaines}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
    ) as progression:
        collecter_sous_domaines(domaines, sources, infos_fqdn, progression)

        moteur = MoteurDns(timeout=3)
        tache_wildcard = progression.add_task("[yellow]Jokers DNS...", total=len(domaines))
        jokers = 0
        for domaine in domaines:
            if moteur.detecter_wildcard(domaine):
                jokers += 1
            progression.advance(tache_wildcard)
        texte_joker = (
            f"[red]{jokers} joker(s)[/red]" if jokers else "[green]aucun joker[/green]"
        )
        progression.update(tache_wildcard, description=f"[yellow]Jokers DNS ({texte_joker})")

        actifs = []
        if types_dns:
            tache_dns = progression.add_task(
                "[magenta]Résolution DNS...",
                total=len(infos_fqdn) * len(types_dns),
            )
            for fqdn, info in infos_fqdn.items():
                for type_enregistrement in types_dns:
                    actifs.extend(
                        moteur.resoudre(fqdn, type_enregistrement, info["source"], info["root"])
                    )
                    progression.advance(tache_dns)
            progression.update(tache_dns, description="[magenta]Résolution DNS terminée")

        if "httpx (Découverte Web HTTP/HTTPS)" in modules:
            tache_http = progression.add_task("[blue]Sonde HTTP...", total=100)
            actifs_http = MoteurHttpx.executer(infos_fqdn)
            actifs.extend(actifs_http)
            progression.update(
                tache_http,
                completed=100,
                description=f"[blue]Sonde HTTP ({len(actifs_http)} service(s))",
            )

    # Regroupe par nom, et place les lignes DNS avant la ligne HTTP du même nom.
    actifs.sort(key=lambda actif: (actif.fqdn, actif.source == "httpx"))
    afficher_apercu(actifs, len(infos_fqdn))

    chemin_csv, chemin_json = exporter(actifs)
    console.print("\n[bold green]Exports :[/bold green]")
    console.print(f"  - {chemin_csv}")
    console.print(f"  - {chemin_json}\n")


def afficher_apercu(actifs: List[Actif], nombre_fqdn: int):
    """Montre les 20 premières lignes. Le fichier exporté contient le reste."""
    console.print(f"\n[bold]{nombre_fqdn} FQDN, {len(actifs)} ligne(s). Aperçu :[/bold]")
    tableau = Table(show_header=True, header_style="bold blue")
    tableau.add_column("FQDN", style="cyan")
    tableau.add_column("Source", style="dim")
    tableau.add_column("Type")
    tableau.add_column("Statut")
    tableau.add_column("Valeur", overflow="fold")

    for actif in actifs[:20]:
        if actif.source == "httpx":
            couleur = _couleur_http(actif.http_status)
            valeur = actif.http_title or actif.http_server or "-"
            if actif.http_title and actif.http_server:
                valeur = f"{actif.http_title} ({actif.http_server})"
            tableau.add_row(
                actif.fqdn,
                "httpx",
                "WEB",
                f"[{couleur}]{actif.http_status}[/{couleur}]",
                _raccourcir(f"{actif.http_url} | {valeur}"),
            )
        else:
            couleur = "green" if actif.status == "NOERROR" else "red"
            tableau.add_row(
                actif.fqdn,
                actif.source,
                actif.dns_type or "-",
                f"[{couleur}]{actif.status}[/{couleur}]",
                _raccourcir(actif.value or "-"),
            )

    console.print(tableau)
    if len(actifs) > 20:
        console.print(f"[dim]{len(actifs) - 20} autre(s) ligne(s) dans l'export.[/dim]")


def _couleur_http(statut: Optional[int]) -> str:
    texte = str(statut)
    if texte.startswith("2"):
        return "green"
    if texte.startswith("3"):
        return "yellow"
    return "red"


def _raccourcir(texte: str, limite: int = 45) -> str:
    if len(texte) <= limite:
        return texte
    return texte[: limite - 3] + "..."


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[red]Interrompu.[/red]")
        sys.exit(0)
