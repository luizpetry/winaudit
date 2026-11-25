"""Relatorio HTML autocontido (sem dependencias externas)."""
from __future__ import annotations

import html
import platform
from datetime import datetime
from string import Template

from ..models import CheckResult, Severity, Status

SEV_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.NONE: 4}
STATUS_ORDER = {Status.FAIL: 0, Status.WARN: 1, Status.INFO: 2, Status.PASS: 3}
STATUS_LABEL = {Status.FAIL: "Falha", Status.WARN: "Alerta", Status.PASS: "OK", Status.INFO: "Info"}
SEV_LABEL = {Severity.CRITICAL: "Critica", Severity.HIGH: "Alta", Severity.MEDIUM: "Media",
             Severity.LOW: "Baixa", Severity.NONE: ""}

PAGE = Template("""<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WinAudit: $host</title>
<style>
:root {
  --bg: #f6f7f9; --surface: #ffffff; --border: #e3e6ea; --text: #1b1f24; --muted: #5f6b7a;
  --pass: #1f8a4c; --warn: #b26b00; --fail: #c62828; --info: #2364aa;
  --pass-bg: #e6f4ec; --warn-bg: #fdf1dc; --fail-bg: #fde8e8; --info-bg: #e5eef9;
  --code-bg: #f0f2f5; --ring-track: #e3e6ea;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0f1216; --surface: #171b21; --border: #2a3039; --text: #e6e9ee; --muted: #9aa5b4;
    --pass: #4cc283; --warn: #f0a83a; --fail: #ff6b6b; --info: #6aa8ef;
    --pass-bg: #15291e; --warn-bg: #2e2412; --fail-bg: #331819; --info-bg: #152335;
    --code-bg: #10141a; --ring-track: #2a3039;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.5 "Segoe UI", system-ui, -apple-system, sans-serif; }
.wrap { max-width: 980px; margin: 0 auto; padding: 32px 16px 64px; }
header { display: flex; gap: 28px; align-items: center; flex-wrap: wrap;
  background: var(--surface); border: 1px solid var(--border); border-radius: 14px; padding: 24px; }
.ring { position: relative; width: 132px; height: 132px; flex: none; }
.ring svg { transform: rotate(-90deg); }
.ring .num { position: absolute; inset: 0; display: grid; place-items: center; text-align: center; }
.ring .num b { font-size: 34px; line-height: 1; display: block; }
.ring .num span { color: var(--muted); font-size: 13px; }
.meta h1 { margin: 0 0 4px; font-size: 22px; }
.meta p { margin: 2px 0; color: var(--muted); }
.counts { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 12px; }
.chip { border: 1px solid var(--border); background: var(--surface); color: var(--text);
  border-radius: 999px; padding: 5px 12px; font: inherit; font-size: 13px; cursor: pointer; }
.chip[aria-pressed="true"] { border-color: var(--text); font-weight: 600; }
.chip i { font-style: normal; font-weight: 700; margin-right: 4px; }
.chip.fail i { color: var(--fail); } .chip.warn i { color: var(--warn); }
.chip.pass i { color: var(--pass); } .chip.info i { color: var(--info); }
h2 { font-size: 15px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); margin: 32px 0 10px; }
.card { background: var(--surface); border: 1px solid var(--border); border-left: 4px solid var(--border);
  border-radius: 10px; padding: 14px 16px; margin-bottom: 10px; }
.card.FAIL { border-left-color: var(--fail); } .card.WARN { border-left-color: var(--warn); }
.card.PASS { border-left-color: var(--pass); } .card.INFO { border-left-color: var(--info); }
.top { display: flex; gap: 10px; align-items: baseline; flex-wrap: wrap; }
.top h3 { margin: 0; font-size: 15px; flex: 1 1 260px; }
.badge { font-size: 12px; font-weight: 600; padding: 2px 8px; border-radius: 6px; white-space: nowrap; }
.badge.FAIL { background: var(--fail-bg); color: var(--fail); }
.badge.WARN { background: var(--warn-bg); color: var(--warn); }
.badge.PASS { background: var(--pass-bg); color: var(--pass); }
.badge.INFO { background: var(--info-bg); color: var(--info); }
.sev { color: var(--muted); font-size: 12px; }
.details { margin: 6px 0 0; color: var(--muted); }
.risks { margin-top: 10px; padding: 10px 12px; border-radius: 8px; background: var(--fail-bg); }
.card.WARN .risks { background: var(--warn-bg); }
.risks b { font-size: 13px; }
.risks ul { margin: 4px 0 0; padding-left: 18px; }
.risks li { margin: 2px 0; }
.fix { margin-top: 10px; background: var(--code-bg); border-radius: 8px; padding: 10px 12px;
  display: flex; gap: 10px; align-items: flex-start; }
.fix code { flex: 1; font: 13px/1.5 Consolas, ui-monospace, monospace; white-space: pre-wrap; word-break: break-word; }
.fix button { flex: none; font: inherit; font-size: 12px; border: 1px solid var(--border);
  background: var(--surface); color: var(--text); border-radius: 6px; padding: 3px 8px; cursor: pointer; }
details { margin-top: 8px; }
summary { cursor: pointer; color: var(--muted); font-size: 13px; }
details ul { margin: 6px 0 0; padding-left: 18px; font: 12.5px/1.6 Consolas, ui-monospace, monospace;
  max-height: 320px; overflow: auto; word-break: break-all; }
footer { margin-top: 40px; color: var(--muted); font-size: 13px; text-align: center; }
.hidden { display: none; }
</style>
</head>
<body>
<div class="wrap">
<header>
  <div class="ring" aria-label="Nota $score de 100">
    <svg width="132" height="132" viewBox="0 0 132 132">
      <circle cx="66" cy="66" r="56" fill="none" stroke="var(--ring-track)" stroke-width="12"/>
      <circle cx="66" cy="66" r="56" fill="none" stroke="$ring_color" stroke-width="12"
        stroke-linecap="round" stroke-dasharray="$dash 352"/>
    </svg>
    <div class="num"><div><b>$score</b><span>nota $grade</span></div></div>
  </div>
  <div class="meta">
    <h1>Relatorio de seguranca do Windows</h1>
    <p>$host &middot; $os</p>
    <p>$when &middot; $privilege</p>
    <div class="counts" role="group" aria-label="Filtrar">
      <button class="chip" data-f="all" aria-pressed="true">Todos</button>
      <button class="chip fail" data-f="FAIL" aria-pressed="false"><i>$n_fail</i>falhas</button>
      <button class="chip warn" data-f="WARN" aria-pressed="false"><i>$n_warn</i>alertas</button>
      <button class="chip pass" data-f="PASS" aria-pressed="false"><i>$n_pass</i>ok</button>
      <button class="chip info" data-f="INFO" aria-pressed="false"><i>$n_info</i>info</button>
    </div>
  </div>
</header>
$sections
<footer>Gerado pelo WinAudit &middot; verificacao somente leitura, nenhuma configuracao foi alterada.</footer>
</div>
<script>
document.querySelectorAll('.chip').forEach(function (b) {
  b.addEventListener('click', function () {
    var f = b.dataset.f;
    document.querySelectorAll('.chip').forEach(function (x) { x.setAttribute('aria-pressed', x === b); });
    document.querySelectorAll('.card').forEach(function (c) {
      c.classList.toggle('hidden', f !== 'all' && !c.classList.contains(f));
    });
    document.querySelectorAll('section').forEach(function (s) {
      s.classList.toggle('hidden', !s.querySelector('.card:not(.hidden)'));
    });
  });
});
document.querySelectorAll('.fix button').forEach(function (b) {
  b.addEventListener('click', function () {
    var t = b.previousElementSibling.textContent;
    navigator.clipboard.writeText(t).then(function () {
      b.textContent = 'Copiado'; setTimeout(function () { b.textContent = 'Copiar'; }, 1500);
    });
  });
});
</script>
</body>
</html>
""")


def _card(f) -> str:
    e = html.escape
    sev = SEV_LABEL[f.severity] if f.status in (Status.FAIL, Status.WARN) else ""
    parts = [f'<div class="card {f.status.value}"><div class="top">'
             f'<span class="badge {f.status.value}">{STATUS_LABEL[f.status]}</span>'
             f'<h3>{e(f.title)}</h3>'
             + (f'<span class="sev">Severidade {sev.lower()}</span>' if sev else "")
             + "</div>"]
    if f.details:
        parts.append(f'<p class="details">{e(f.details)}</p>')
    if f.risks:
        items = "".join(f"<li>{e(x)}</li>" for x in f.risks)
        parts.append(f'<div class="risks"><b>Riscos de manter assim</b><ul>{items}</ul></div>')
    if f.remediation:
        parts.append(f'<div class="fix"><code>{e(f.remediation)}</code><button type="button">Copiar</button></div>')
    if f.evidence:
        items = "".join(f"<li>{e(x)}</li>" for x in f.evidence)
        parts.append(f"<details><summary>{len(f.evidence)} item(ns)</summary><ul>{items}</ul></details>")
    parts.append("</div>")
    return "".join(parts)


def render(results: list[CheckResult], score: int, grade: str, is_admin: bool) -> str:
    by_cat: dict[str, list] = {}
    for r in results:
        by_cat.setdefault(r.category, []).extend(r.findings)

    def cat_rank(item):
        fs = item[1]
        return min((STATUS_ORDER[f.status] for f in fs), default=9), item[0]

    sections = []
    for cat, fs in sorted(by_cat.items(), key=cat_rank):
        fs = sorted(fs, key=lambda f: (STATUS_ORDER[f.status], SEV_ORDER[f.severity]))
        sections.append(f"<section><h2>{html.escape(cat)}</h2>{''.join(_card(f) for f in fs)}</section>")

    all_f = [f for r in results for f in r.findings]
    count = lambda s: sum(1 for f in all_f if f.status == s)
    ring = "var(--pass)" if score >= 80 else "var(--warn)" if score >= 60 else "var(--fail)"
    return PAGE.substitute(
        host=html.escape(platform.node()),
        os=html.escape(f"{platform.system()} {platform.release()} ({platform.version()})"),
        when=datetime.now().strftime("%d/%m/%Y %H:%M"),
        privilege="executado como administrador" if is_admin else "executado sem privilegios de administrador",
        score=score, grade=grade, dash=round(352 * score / 100), ring_color=ring,
        n_fail=count(Status.FAIL), n_warn=count(Status.WARN), n_pass=count(Status.PASS), n_info=count(Status.INFO),
        sections="".join(sections),
    )
