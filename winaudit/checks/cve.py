"""Consulta CVEs conhecidas na API do NVD (opcional, ativado com --cve).

Duas camadas:

* Catalogo curado (``--cve``): programas comuns no Windows com o CPE ja
  conhecido. So vendor/produto/versao desses programas sao enviados ao NVD.
* Descoberta automatica (``--cve-auto``): para os demais programas instalados,
  procura o produto no dicionario de CPE do NVD pelo nome e fabricante. Envia o
  nome dos programas (nunca nomes que contenham o usuario ou o nome do PC).
"""
from __future__ import annotations

import json
import os
import platform
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from ..models import Severity, failed, info, passed, warn
from . import check

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
CACHE_DIR = Path.home() / ".winaudit" / "cache"
CACHE_TTL = 24 * 3600
RESOLVE_TTL = 30 * 24 * 3600  # nome -> CPE muda raramente


def _parts(n):
    return lambda v: ".".join(re.split(r"[-+ ]", v)[0].split(".")[:n])


def _same(v):
    return v


# (regex no nome, vendor CPE, produto CPE, normalizador de versao, versao vem do nome?)
# A ordem importa: a primeira regex que casar vence.
CATALOG = [
    # compactadores
    (r"^7-Zip", "7-zip", "7-zip", _same, False),
    (r"^WinRAR", "rarlab", "winrar", _parts(2), False),
    (r"^WinZip", "winzip", "winzip", _parts(2), False),
    # navegadores e e-mail
    (r"^Google Chrome$", "google", "chrome", _same, False),
    (r"^Mozilla Firefox", "mozilla", "firefox", _same, False),
    (r"^Mozilla Thunderbird", "mozilla", "thunderbird", _same, False),
    (r"^Microsoft Edge$", "microsoft", "edge_chromium", _same, False),
    (r"^Brave$", "brave", "brave", _same, False),
    (r"^Opera( Stable)? \d", "opera", "opera_browser", _same, False),
    (r"^Tor Browser", "torproject", "tor_browser", _same, False),
    # midia e documentos
    (r"^VLC media player", "videolan", "vlc_media_player", _same, False),
    (r"^Adobe Acrobat", "adobe", "acrobat_reader_dc", _same, False),
    (r"^Foxit PDF Reader", "foxit", "pdf_reader", _same, False),
    (r"^SumatraPDF", "sumatrapdfreader", "sumatrapdf", _same, False),
    (r"^LibreOffice", "libreoffice", "libreoffice", _parts(3), False),
    (r"^GIMP", "gimp", "gimp", _parts(3), False),
    (r"^Inkscape", "inkscape", "inkscape", _parts(3), False),
    (r"^ImageMagick", "imagemagick", "imagemagick", _parts(3), False),
    (r"^GPL Ghostscript", "artifex", "ghostscript", _parts(2), False),
    (r"^Audacity", "audacityteam", "audacity", _parts(3), False),
    (r"^calibre", "calibre-ebook", "calibre", _parts(3), False),
    (r"^Notepad\+\+", "notepad-plus-plus", "notepad\\+\\+", _same, False),
    # comunicacao
    (r"^Telegram Desktop", "telegram", "telegram_desktop", _parts(3), False),
    (r"^Zoom", "zoom", "meetings", _parts(3), False),
    # P2P
    (r"^qBittorrent", "qbittorrent", "qbittorrent", _parts(3), False),
    (r"^(µ|u)Torrent", "bittorrent", "utorrent", _same, False),
    # acesso remoto e VPN
    (r"^TeamViewer", "teamviewer", "teamviewer", _same, False),
    (r"^AnyDesk", "anydesk", "anydesk", _same, False),
    (r"^RustDesk", "rustdesk", "rustdesk", _parts(3), False),
    (r"^TightVNC", "tightvnc", "tightvnc", _parts(3), False),
    (r"^UltraVNC", "uvnc", "ultravnc", _parts(3), False),
    (r"^PuTTY", "putty", "putty", _parts(2), False),
    (r"^WinSCP", "winscp", "winscp", _same, False),
    (r"^FileZilla", "filezilla-project", "filezilla_client", _same, False),
    (r"^OpenVPN Connect", "openvpn", "connect", _parts(3), False),
    (r"^OpenVPN \d", "openvpn", "openvpn", _parts(3), False),
    # seguranca e senhas
    (r"^KeePass Password Safe", "keepass", "keepass", _same, False),
    (r"^KeePassXC", "keepassxc", "keepassxc", _parts(3), False),
    (r"^VeraCrypt", "idrix", "veracrypt", _same, False),
    (r"^Wireshark", "wireshark", "wireshark", _same, False),
    (r"^Nmap", "nmap", "nmap", _same, False),
    # desenvolvimento
    (r"^Git$|^Git version", "git-scm", "git", _parts(3), False),
    (r"^Python (\d+\.\d+\.\d+)", "python", "python", _same, True),
    (r"^Node\.js", "nodejs", "node.js", _same, False),
    (r"^Go Programming Language", "golang", "go", _parts(3), False),
    (r"^Microsoft Visual Studio Code", "microsoft", "visual_studio_code", _parts(3), False),
    (r"^PyCharm", "jetbrains", "pycharm", _parts(2), True),
    (r"^IntelliJ IDEA", "jetbrains", "intellij_idea", _parts(2), True),
    (r"^Postman", "postman", "postman", _parts(3), False),
    (r"^Docker Desktop", "docker", "desktop", _parts(3), False),
    (r"^PostgreSQL", "postgresql", "postgresql", _parts(2), False),
    (r"^MySQL Server", "oracle", "mysql", _parts(3), False),
    (r"^XAMPP", "apachefriends", "xampp", _parts(3), False),
    # virtualizacao e utilitarios
    (r"^Oracle VirtualBox|^Oracle VM VirtualBox", "oracle", "vm_virtualbox", _parts(3), False),
    (r"^VMware Workstation", "vmware", "workstation", _parts(3), False),
    (r"^Microsoft PowerToys|^PowerToys", "microsoft", "powertoys", _parts(3), False),
    (r"^CPUID CPU-Z", "cpuid", "cpu-z", _parts(2), False),
    (r"^MSI Afterburner", "msi", "afterburner", _parts(3), False),
]


def match_catalog(apps: list[dict]) -> list[tuple[str, str]]:
    """Retorna [(nome legivel, cpeName)] sem duplicatas."""
    return [(label, cpe) for label, cpe, _ in _match_catalog(apps)]


def _match_catalog(apps: list[dict]) -> list[tuple[str, str, dict]]:
    out, seen = [], set()
    for a in apps:
        for rx, vendor, product, norm, from_name in CATALOG:
            m = re.search(rx, a["name"], re.I)
            if not m:
                continue
            if from_name and m.groups():
                raw = m.group(1)
            elif from_name:  # versao no nome, sem grupo: primeiro numero com ponto
                vm = re.search(r"\d+(\.\d+)+", a["name"])
                raw = vm.group(0) if vm else a["version"]
            else:
                raw = a["version"]
            version = norm(raw.strip()) if raw else ""
            if not re.match(r"^\d", version):
                break
            cpe = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
            if cpe not in seen:
                seen.add(cpe)
                label = a["name"] if version in a["name"] else f"{a['name']} {version}"
                out.append((label, cpe, a))
            break
    return out


# ---------------------------------------------------------------- descoberta automatica

# coisas que nao vale a pena (ou nao da) procurar no NVD
SKIP_AUTO = re.compile(
    r"\bKB\d{6,}|redistributable|\bruntime\b|\bdrivers?\b|update for|language pack|\bsdk\b|"
    r"development kit|\bsetup\b|uninstall|\bhelper\b|add-?in|odbc|ole db|^gdr \d|hotfix|fonts?\b|"
    r"\bvss\b|update health|maintenance service|\bdocumentation\b",
    re.I)
CORP_WORDS = {"inc", "corporation", "corp", "ltd", "llc", "gmbh", "co", "sa", "ag", "bv", "srl",
              "limited", "software", "technologies", "technology", "foundation", "the", "and", "of"}
NOISE_WORDS = {"x64", "x86", "64", "32", "bit", "64bit", "32bit", "user", "version", "for", "windows",
               "the", "and", "edition", "en", "us", "pt", "br"}


def _tokens(s: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9+]+", s.lower()) if t}


def _compact(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def clean_name(name: str) -> str:
    """'Mozilla Firefox (x64 pt-BR) 160.0.1' -> 'Mozilla Firefox'."""
    s = re.sub(r"\(.*?\)|\[.*?\]", " ", name)
    s = re.sub(r"\s[-–]\s.*$", " ", s)  # 'Produto - 1.2.3' / 'Produto - Canal'
    s = re.sub(r"\bv?\d+(\.\d+)+\S*", " ", s)  # numeros de versao
    s = re.sub(r"\b(version|x64|x86|64-bit|32-bit|[a-z]{2}-[A-Z]{2})\b", " ", s, flags=re.I)
    s = re.sub(r"[®™©]", "", s)
    return re.sub(r"\s+", " ", s).strip(" -,")


def _private_words() -> list[str]:
    words = [os.environ.get("USERNAME", ""), platform.node()]
    try:
        words.append(os.getlogin())
    except OSError:
        pass
    return [w.lower() for w in words if w and len(w) >= 3]


def auto_candidates(apps: list[dict], exclude: set[int] = frozenset()) -> list[tuple[dict, str]]:
    """Programas que a descoberta automatica vai tentar identificar: [(app, nome limpo)]."""
    private = _private_words()
    out, seen = [], set()
    for a in apps:
        if id(a) in exclude or not re.match(r"^\d", a.get("version", "")):
            continue
        name = a["name"]
        low = name.lower()
        if SKIP_AUTO.search(name) or any(p in low for p in private):
            continue  # nunca manda o nome do usuario/PC para fora
        clean = clean_name(name)
        if len(clean) < 3 or not (_tokens(clean) - NOISE_WORDS):
            continue
        if clean.lower() in seen:
            continue
        seen.add(clean.lower())
        out.append((a, clean))
    return out


def pick_cpe(clean: str, publisher: str, products: list[str]) -> tuple[str, str] | None:
    """Escolhe o (vendor, produto) do dicionario de CPE que corresponde ao programa.

    Conservador de proposito: e melhor nao identificar do que apontar CVEs de
    outro produto. Exige que o fabricante bata com o Publisher (ou o nome) e que
    as palavras do produto sejam as do nome (no maximo uma a mais, ex.: 'vm_virtualbox').
    """
    name_words = [t for t in _words(clean) if t not in NOISE_WORDS]
    pub_words = [t for t in _words(publisher) if t not in CORP_WORDS]
    stats: dict[tuple[str, str], int] = {}
    for cpe in products:
        p = cpe.split(":")
        if len(p) > 5 and p[2] == "a":
            stats[(p[3], p[4])] = stats.get((p[3], p[4]), 0) + 1

    exact: list[tuple[int, tuple[str, str]]] = []
    near: list[tuple[int, tuple[str, str]]] = []
    for (vendor, product), count in stats.items():
        if not _vendor_ok(vendor, pub_words, name_words):
            continue
        vend_tok = _tokens(vendor.replace("_", " "))
        core_words = [t for t in name_words if t not in vend_tok and t not in EDITION_WORDS] or name_words
        core = set(core_words)
        pcore = (_tokens(product.replace("_", " ")) - vend_tok) or _tokens(product)
        pc = _compact(product)
        if pcore == core or pc in (_compact("".join(core_words)), _compact(clean)):
            exact.append((count, (vendor, product)))
        elif core < pcore and len(pcore - core) == 1:
            near.append((count, (vendor, product)))
    best_exact = max(exact, default=None)
    best_near = max(near, default=None)
    # 'oracle:virtualbox' (8 entradas antigas) perde para 'oracle:vm_virtualbox' (centenas)
    if best_near and (not best_exact or best_near[0] > 10 * best_exact[0]):
        return best_near[1]
    return best_exact[1] if best_exact else None


# sufixos que aparecem no vendor do CPE mas nao no Publisher ('valvesoftware', 'konghq')
VENDOR_SUFFIXES = {"", "hq", "inc", "software", "soft", "project", "team", "dev", "labs", "app", "apps",
                   "io", "org", "corp", "group", "studio", "studios", "games"}
EDITION_WORDS = {"community", "edition", "professional", "pro", "free", "stable", "app", "lts",
                 "portable", "enterprise", "standard", "personal"}


def _words(s: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9+]+", s.lower()) if t]


def _vendor_ok(vendor: str, pub_words: list[str], name_words: list[str]) -> bool:
    """O vendor do CPE e o fabricante do programa? Compara inteiro, nao por palavra solta
    ('slack_morphism_project' nao e 'Slack Technologies')."""
    vc = _compact(vendor)
    if len(vc) < 2:
        return False
    if pub_words:
        pc = "".join(pub_words)
        if vc == pc or vc == pub_words[0]:
            return True
        if len(vc) >= 3 and pc.startswith(vc):  # 'portswigger' / 'PortSwigger Web Security'
            return True
        return vc.startswith(pc) and vc[len(pc):] in VENDOR_SUFFIXES or \
            vc.startswith(pub_words[0]) and len(pub_words[0]) >= 4 and vc[len(pub_words[0]):] in VENDOR_SUFFIXES
    # sem Publisher: aceita so se o nome comeca com o vendor ('Oracle VirtualBox')
    return len(vc) >= 3 and "".join(name_words).startswith(vc)


class _Throttle:
    """Respeita o limite publico do NVD entre requisicoes de rede."""

    def __init__(self, delay: float):
        self.delay, self.last = delay, 0.0

    def wait(self):
        gap = time.monotonic() - self.last
        if self.last and gap < self.delay:
            time.sleep(self.delay - gap)
        self.last = time.monotonic()


def _get_json(url: str) -> dict:
    headers = {"User-Agent": "winaudit"}
    key = os.environ.get("NVD_API_KEY")
    if key:
        headers["apiKey"] = key
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.load(resp)


RESOLVE_CACHE = "cpe-resolve.json"


def _load_resolve_cache() -> dict:
    p = CACHE_DIR / RESOLVE_CACHE
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    now = time.time()
    return {k: v for k, v in data.items() if now - v.get("ts", 0) < RESOLVE_TTL}


def _save_resolve_cache(cache: dict):
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    (CACHE_DIR / RESOLVE_CACHE).write_text(json.dumps(cache), encoding="utf-8")


def resolve_cpe(clean: str, publisher: str, cache: dict, throttle: _Throttle) -> tuple[str, str] | None:
    key = f"{clean.lower()}|{publisher.lower()}"
    if key in cache:
        hit = cache[key].get("cpe")
        return tuple(hit) if hit else None
    throttle.wait()
    url = CPE_API + "?" + urllib.parse.urlencode({"keywordSearch": clean, "resultsPerPage": 1000})
    data = _get_json(url)
    names = [p["cpe"]["cpeName"] for p in data.get("products", []) if not p["cpe"].get("deprecated")]
    hit = pick_cpe(clean, publisher, names)
    cache[key] = {"cpe": list(hit) if hit else None, "ts": time.time()}
    return hit


def _auto_version(v: str) -> str:
    m = re.match(r"\d+(\.\d+)*", v.strip())
    return m.group(0) if m else ""


# ---------------------------------------------------------------- CISA KEV

# Catalogo publico da CISA com as CVEs que comprovadamente foram exploradas em
# ataques reais. E um download unico do arquivo inteiro: nada sobre o PC e enviado.
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE = "kev.json"


def load_kev() -> tuple[dict[str, dict], str | None]:
    """Retorna ({cveID: {added, ransomware}}, erro). Usa cache de 24h; se o download
    falhar, cai para o cache antigo, se houver."""
    path = CACHE_DIR / KEV_CACHE
    fresh = path.exists() and time.time() - path.stat().st_mtime < CACHE_TTL
    error = None
    if not fresh:
        try:
            data = _get_json(KEV_URL)
            slim = {v["cveID"]: {"added": v.get("dateAdded", ""),
                                 "ransomware": v.get("knownRansomwareCampaignUse") == "Known"}
                    for v in data.get("vulnerabilities", []) if v.get("cveID")}
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(slim), encoding="utf-8")
            return slim, None
        except Exception as e:
            error = f"{type(e).__name__}: {e}"
    try:
        return json.loads(path.read_text(encoding="utf-8")), error
    except (OSError, ValueError):
        return {}, error or "cache do KEV ilegivel"


# ---------------------------------------------------------------- consulta de CVEs

CACHE_VERSION = "v5"  # muda quando a logica de filtro ou os campos salvos mudam
MAX_PAGES = 6
OTHER_PLATFORM = re.compile(r"\b(on|for) (Android|iOS|Mac|macOS|OS X|Linux|ChromeOS|Chrome OS)\b", re.I)


def _cache_path(cpe: str) -> Path:
    return CACHE_DIR / (re.sub(r"[^A-Za-z0-9._-]", "_", cpe) + f".{CACHE_VERSION}.json")


def _cleanup_old_cache():
    """Apaga respostas salvas por versoes antigas do filtro (nao sao mais lidas)."""
    if not CACHE_DIR.is_dir():
        return
    for f in CACHE_DIR.glob("cpe_*.v*.json"):
        if not f.name.endswith(f".{CACHE_VERSION}.json"):
            try:
                f.unlink()
            except OSError:
                pass


def _vtuple(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v)) or (0,)


def _in_range(version: str, m: dict) -> bool | None:
    """True/False se a versao esta na faixa do cpeMatch; None se nao ha faixa definida."""
    keys = ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding")
    if not any(k in m for k in keys):
        return None
    v = _vtuple(version)
    if "versionStartIncluding" in m and v < _vtuple(m["versionStartIncluding"]):
        return False
    if "versionStartExcluding" in m and v <= _vtuple(m["versionStartExcluding"]):
        return False
    if "versionEndIncluding" in m and v > _vtuple(m["versionEndIncluding"]):
        return False
    if "versionEndExcluding" in m and v >= _vtuple(m["versionEndExcluding"]):
        return False
    return True


def affects(cve: dict, vendor: str, product: str, version: str) -> bool:
    """Confere localmente se a CVE realmente afeta esta versao no Windows.

    O NVD devolve qualquer CVE cujo CPE "casa" com o nome, inclusive entradas
    antigas sem versao definida e falhas so de outras plataformas. Aqui so
    contamos quando ha faixa/versao explicita que cobre a versao instalada.
    """
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    if OTHER_PLATFORM.search(desc) and "windows" not in desc.lower():
        return False
    for config in cve.get("configurations", []):
        matches = [m for node in config.get("nodes", []) for m in node.get("cpeMatch", [])]
        platforms = [m["criteria"].split(":") for m in matches if not m.get("vulnerable")]
        os_platforms = [p for p in platforms if len(p) > 4 and p[2] == "o"]
        if os_platforms and not any(p[3] == "microsoft" for p in os_platforms):
            continue  # so afeta Android/macOS/Linux etc.
        for m in matches:
            if not m.get("vulnerable"):
                continue
            parts = m["criteria"].split(":")
            if len(parts) < 6 or parts[3] != vendor or parts[4] != product:
                continue
            crit_ver = parts[5]
            if crit_ver not in ("*", "-"):
                if _vtuple(crit_ver) == _vtuple(version):
                    return True
                continue
            if _in_range(version, m):
                return True
    return False


def _fetch(cpe: str, start: int) -> dict:
    # noRejected e um parametro sem valor na API do NVD
    url = API + "?" + urllib.parse.urlencode({"cpeName": cpe, "startIndex": start}) + "&noRejected"
    try:
        return _get_json(url)
    except urllib.error.HTTPError as e:
        if e.code == 404:  # CPE inexistente no dicionario
            return {"vulnerabilities": [], "totalResults": 0}
        raise


def query_nvd(cpe: str, throttle: _Throttle | None = None) -> list[dict]:
    cp = _cache_path(cpe)
    if cp.exists() and time.time() - cp.stat().st_mtime < CACHE_TTL:
        return json.loads(cp.read_text(encoding="utf-8"))

    _, _, _, vendor, product, version, *_ = cpe.split(":")
    cves, start = [], 0
    for _ in range(MAX_PAGES):
        if throttle:
            throttle.wait()
        data = _fetch(cpe, start)
        vulns = data.get("vulnerabilities", [])
        cves += [_summarize(v["cve"]) for v in vulns if affects(v["cve"], vendor, product, version)]
        start += len(vulns)
        if not vulns or start >= data.get("totalResults", 0):
            break
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cp.write_text(json.dumps(cves), encoding="utf-8")
    return cves


def _summarize(cve: dict) -> dict:
    score, vector = None, ""
    metrics = cve.get("metrics", {})
    for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(k):
            data = metrics[k][0]["cvssData"]
            score, vector = data.get("baseScore"), data.get("vectorString", "")
            break
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    # descricao inteira: a classificacao de riscos depende do texto todo e roda na hora do
    # relatorio, entao ajustes nela nao exigem baixar tudo do NVD de novo
    return {"id": cve["id"], "score": score, "desc": desc, "vector": vector}


# ---------------------------------------------------------------- riscos de manter a versao

# Como a falha pode ser explorada. A primeira que casar vence; a descricao do NVD
# segue um padrao bem regular ("allowed a remote attacker to ... via a crafted HTML page").
# "file" vem antes de "web" porque o texto padrao do ZDI diz "visit a malicious page or
# open a malicious file", e ai o arquivo e o caminho mais especifico.
SCENARIOS = [
    ("file", "Abrir ou extrair um arquivo malicioso (baixado, recebido por e-mail ou chat)",
     re.compile(r"(crafted|malicious|specially crafted|untrusted)[^.]{0,40}?\b(archive|file|document|pdf|image|"
                r"video|audio|media|font|playlist|subtitle|rar|zip|notebook)s?\b", re.I)),
    ("web", "Visitar um site malicioso (ou ver um anuncio malicioso num site normal)",
     re.compile(r"crafted (html|web) ?page|malicious (web ?site|web ?page|page)|compromised the renderer|"
                r"visit(s|ing|ed)? a|while browsing|crafted (url|link)|crafted (javascript|wasm|webassembly)", re.I)),
    ("repo", "Clonar ou abrir um repositorio/projeto malicioso",
     re.compile(r"repositor(y|ies)|\bclon(e|es|ing)\b|submodule|untrusted project|project open|"
                r"open(s|ing)? a (malicious |crafted )?project", re.I)),
    ("authuser", "Alguem que ja tem acesso ao programa (ex.: um usuario do banco de dados) ir alem do permitido",
     re.compile(r"(authenticated|unprivileged|low[- ]privileged|database|server) (user|superuser)|"
                r"attacker with (valid |low )?(credentials|privileges)", re.I)),
    ("local", "Um malware ou usuario que ja esta no PC ganhar mais privilegios",
     re.compile(r"local (user|attacker)|locally|privilege escalation|escalat\w+ (of )?privileges|"
                r"elevat\w+ (of )?privileges|gain (elevated|higher|system) privileges", re.I)),
]
SCENARIO_TEXT = {k: text for k, text, _ in SCENARIOS}
SCENARIO_TEXT.update({
    "network": "Ataque direto pela rede, sem nenhuma acao sua, se o programa estiver acessivel na rede",
    "interaction": "Interagir com conteudo malicioso (link, mensagem, servidor ou arquivo falso)",
    "other": "Situacoes mais especificas (veja a descricao de cada CVE)",
})
IMPACTS = [
    ("code", re.compile(r"execute arbitrary|arbitrary code|code execution|execute (code|commands)|"
                        r"remote code|sandbox escape|command injection|result in takeover", re.I)),
    ("data", re.compile(r"sensitive information|information disclosure|obtain (potentially )?sensitive|"
                        r"read arbitrary|leak|exfiltrat|unauthorized (read )?access to (critical|a subset)", re.I)),
    ("tamper", re.compile(r"(creation, deletion or modification|update, insert or delete) access|"
                          r"overwrite (arbitrary|local) files|write arbitrary files|delete arbitrary files", re.I)),
    ("spoof", re.compile(r"spoof", re.I)),
    ("dos", re.compile(r"denial of service|\bcrash", re.I)),
]
IMPACT_TEXT = {"code": "executar codigo no seu PC", "data": "ler dados que deveriam estar protegidos",
               "tamper": "alterar ou apagar dados e arquivos",
               "spoof": "falsificar o que aparece na tela (ex.: endereco do site)",
               "dos": "travar o programa"}


def _cvss(vector: str) -> dict[str, str]:
    """'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/...' -> {'AV': 'N', 'PR': 'N', 'UI': 'R', ...}"""
    return dict(p.split(":", 1) for p in vector.split("/") if ":" in p and not p.startswith("CVSS"))


def classify_cve(desc: str, vector: str = "") -> tuple[str, list[str]]:
    """Retorna (cenario, impactos) de uma CVE a partir da descricao e do vetor CVSS."""
    impacts = [k for k, rx in IMPACTS if rx.search(desc)]
    for key, _, rx in SCENARIOS:
        if rx.search(desc):
            return key, impacts
    v = _cvss(vector)
    if v.get("AV") == "L":
        return "local", impacts
    if v.get("AV") == "N":
        if v.get("UI", "N") == "N" and v.get("PR", v.get("Au", "N")) == "N":
            return "network", impacts
        if v.get("UI") in ("R", "P", "A"):
            return "interaction", impacts
    return "other", impacts


def risk_summary(cves: list[dict], kev: dict[str, dict] | None = None, limit: int = 4) -> list[str]:
    """Agrupa as CVEs por cenario: 'Visitar um site malicioso: 412 falha(s), 9 ja exploradas; 230 permitem ...'."""
    kev = kev or {}
    groups: dict[str, list[dict]] = {}
    for c in cves:
        if "scenario" not in c:
            c["scenario"], c["impacts"] = classify_cve(c.get("desc", ""), c.get("vector", ""))
        groups.setdefault(c["scenario"], []).append(c)

    def rank(item):
        key, cs = item
        return (sum(c["id"] in kev for c in cs), key != "other", sum("code" in c.get("impacts", []) for c in cs),
                len(cs))

    lines = []
    for key, cs in sorted(groups.items(), key=rank, reverse=True)[:limit]:
        n_kev = sum(c["id"] in kev for c in cs)
        text = f"{SCENARIO_TEXT[key]}: {len(cs)} falha(s)"
        if n_kev:
            text += f", {n_kev} ja explorada(s) em ataques reais"
        counts = {imp: sum(imp in c.get("impacts", []) for c in cs) for imp in IMPACT_TEXT}
        worst = next((imp for imp in IMPACT_TEXT if counts[imp]), None)  # ordem = gravidade
        if worst:
            n = counts[worst]
            who = ("Ela pode" if n == 1 else "Todas podem") if n == len(cs) else                 ("1 delas pode" if n == 1 else f"{n} delas podem")
            text += f". {who} permitir {IMPACT_TEXT[worst]}"
        lines.append(text + ".")
    if len(groups) > limit:
        rest = sum(len(cs) for _, cs in sorted(groups.items(), key=rank, reverse=True)[limit:])
        lines.append(f"Mais {rest} falha(s) em outros cenarios.")
    return lines


def _severity(score: float | None) -> Severity:
    if score is None:
        return Severity.LOW
    if score >= 9:
        return Severity.CRITICAL
    if score >= 7:
        return Severity.HIGH
    if score >= 4:
        return Severity.MEDIUM
    return Severity.LOW


_SEV_RANK = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def _finding(label: str, cpe: str, cves: list[dict], auto: bool, kev: dict[str, dict] | None = None):
    kev = kev or {}
    exploited = [c for c in cves if c["id"] in kev]
    ransomware = [c for c in exploited if kev[c["id"]].get("ransomware")]
    # exploradas primeiro (com ransomware no topo), depois pela nota CVSS
    cves.sort(key=lambda c: (c["id"] in kev, kev.get(c["id"], {}).get("ransomware", False), c["score"] or 0),
              reverse=True)
    top = max((c["score"] or 0 for c in cves), default=0) or None
    sev = _severity(top)
    if exploited:  # explorada de verdade pesa mais que a nota teorica
        floor = Severity.CRITICAL if ransomware else Severity.HIGH
        sev = max(sev, floor, key=_SEV_RANK.index)
    make = failed if sev in (Severity.CRITICAL, Severity.HIGH) else warn
    _, _, _, vendor, product, *_ = cpe.split(":")

    title = f"{label}: {len(cves)} CVE(s) conhecida(s)"
    if exploited:
        title += f", {len(exploited)} explorada(s) em ataques reais"
        details = ((f"{len(exploited)} dessas falhas estao no catalogo KEV da CISA, ou seja, ja foram usadas em "
                    if len(exploited) > 1 else "Essa falha esta no catalogo KEV da CISA, ou seja, ja foi usada em ")
                   + "ataques reais" + (f" ({len(ransomware)} delas por ransomware)" if ransomware else "") +
                   f". Maior nota CVSS: {top}.")
    else:
        details = (f"Maior nota CVSS: {top}. Nenhuma delas consta como explorada em ataques reais "
                   "(catalogo KEV da CISA), mas versoes antigas sao alvo comum.")
    if auto:
        details += (f" Produto identificado automaticamente no NVD como {vendor}/{product};"
                    " confira se e mesmo este programa.")

    def line(c):
        k = kev.get(c["id"])
        tag = ("[EXPLORADA, RANSOMWARE] " if k["ransomware"] else "[EXPLORADA] ") if k else ""
        return f"{tag}{c['id']} (CVSS {c['score']}): {c['desc'][:180]}"

    # mostra todas as exploradas (sao poucas e as mais importantes) + as piores ate completar 8
    shown = cves[:max(8, len(exploited))]
    f = make(f"cve.{vendor}.{product}", title, sev, details,
             "Atualize pelo site oficial ou rode: winget upgrade --all. "
             "Se nao usa o programa, desinstale: programa parado continua vulneravel.",
             [line(c) for c in shown])
    f.risks = risk_summary(cves, kev)
    return f


@check("cve", "Software", order=110, optional=True)
def cve(ctx):
    apps = ctx.shared.get("software")
    if apps is None:
        from .software import inventory
        apps = inventory()
    say = ctx.progress or (lambda msg: None)
    throttle = _Throttle(0.7 if os.environ.get("NVD_API_KEY") else 6.5)  # limites publicos do NVD
    _cleanup_old_cache()

    catalog = _match_catalog(apps)
    targets = [(label, cpe, False, a) for label, cpe, a in catalog]
    findings, errors, unknown = [], [], []

    if ctx.cve_auto:
        matched = {id(a) for _, _, a in catalog}
        candidates = auto_candidates(apps, matched)
        cache = _load_resolve_cache()
        seen = {t[1] for t in targets}
        try:
            for i, (a, clean) in enumerate(candidates, 1):
                say(f"identificando programas no NVD ({i}/{len(candidates)}): {clean}")
                try:
                    hit = resolve_cpe(clean, a.get("publisher", ""), cache, throttle)
                except Exception as e:
                    errors.append(f"{a['name']}: {e}")
                    continue
                version = _auto_version(a["version"])
                if not hit or not version:
                    unknown.append(a["name"])
                    continue
                cpe = f"cpe:2.3:a:{hit[0]}:{hit[1]}:{version}:*:*:*:*:*:*:*"
                if cpe not in seen:
                    seen.add(cpe)
                    label = a["name"] if version in a["name"] else f"{a['name']} {version}"
                    targets.append((label, cpe, True, a))
        finally:
            _save_resolve_cache(cache)

    if not targets:
        findings.append(info("cve.none", "Nenhum programa do catalogo de CVE encontrado",
                             "" if ctx.cve_auto else "Use --cve-auto para tentar identificar os demais programas."))
        return findings

    say("baixando catalogo de falhas exploradas (CISA KEV)")
    kev, kev_error = load_kev()

    # programas vulneraveis, para o 'winaudit update' saber o que atualizar
    vulnerable = ctx.shared.setdefault("vulnerable", [])
    for i, (label, cpe, auto, app) in enumerate(targets, 1):
        say(f"consultando CVEs ({i}/{len(targets)}): {label}")
        try:
            cves = query_nvd(cpe, throttle)
        except Exception as e:
            errors.append(f"{label}: {e}")
            continue
        if cves:
            f = _finding(label, cpe, cves, auto, kev)
            findings.append(f)
            vulnerable.append({"app": app, "label": label, "severity": f.severity, "cves": len(cves),
                               "exploited": sum(c["id"] in kev for c in cves)})

    if kev_error:
        findings.append(info("cve.kev_error",
                             "Catalogo KEV da CISA indisponivel" if not kev else "Catalogo KEV da CISA desatualizado",
                             ("Nao foi possivel saber quais CVEs ja foram exploradas em ataques reais; "
                              "a gravidade usa so a nota CVSS." if not kev else
                              "Usando a copia salva anteriormente.") + f" ({kev_error})"))
    if errors:
        findings.append(info("cve.errors", "Alguns programas nao puderam ser consultados", evidence=errors))
    if unknown:
        findings.append(info("cve.unknown", f"{len(unknown)} programa(s) nao identificados no NVD",
                             "Nao foi possivel associar estes programas a um produto do NVD com seguranca, "
                             "entao eles nao foram verificados.", unknown))
    if not any(f.status.value in ("FAIL", "WARN") for f in findings):
        findings.append(passed("cve.clean", "Nenhuma CVE conhecida nos programas verificados",
                               f"{len(targets)} programa(s) consultado(s) no NVD."))
    return findings
