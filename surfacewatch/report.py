"""Tek dosyalık HTML rapor.

* Harici bağımlılık, CDN ya da JavaScript yok: e-postayla gönderilebilir,
  çevrimdışı açılabilir. Detaylar <details> ile açılır/kapanır.
* Tüm değerler html.escape ile kaçırılır. Bulgu içerikleri (banner, header,
  CVE açıklaması, subdomain adı) uzak sistemlerden gelir ve saldırgan
  kontrolünde olabilir; rapor açıldığında stored XSS oluşmamalı.
* CSP meta etiketi script çalıştırmayı tamamen kapatır (ikinci savunma katmanı).
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from html import escape
from typing import Any

from . import __version__
from .core.diff import DiffResult
from .core.models import SEVERITIES, Finding
from .core.storage import ScanRecord

_ORDER = {s: i for i, s in enumerate(SEVERITIES)}
_COLOR = {"critical": "#dc2626", "high": "#ea580c", "medium": "#ca8a04", "low": "#2563eb", "info": "#6b7280"}
_MODULE_TITLE = {"network": "Ağ servisleri", "osint": "Pasif OSINT (DNS, e-posta, subdomain)",
                 "web": "Web yapılandırması", "vuln": "Bilinen zafiyetler (CVE)"}

_CSS = """
*{box-sizing:border-box}body{margin:0;font:14px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#0b0f17;color:#e5e7eb}
main{max-width:1150px;margin:0 auto;padding:32px 20px 60px}h1{font-size:24px;margin:0 0 4px}
h2{font-size:17px;margin:36px 0 12px;padding-bottom:6px;border-bottom:1px solid #1f2937}h3{font-size:14px;margin:20px 0 8px;color:#cbd5e1}
.muted{color:#94a3b8;font-size:13px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-top:20px}
.card{background:#111827;border:1px solid #1f2937;border-radius:10px;padding:14px}.card .n{font-size:26px;font-weight:700}
.card .l{color:#94a3b8;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
table{width:100%;border-collapse:collapse;background:#111827;border:1px solid #1f2937;border-radius:10px;overflow:hidden;margin-bottom:8px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid #1f2937;vertical-align:top}
th{color:#94a3b8;font-weight:600;font-size:12px;text-transform:uppercase}tr:last-child td{border-bottom:0}
.sev{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:700;color:#fff;text-transform:uppercase}
code{font-family:ui-monospace,Consolas,monospace;font-size:12px;color:#cbd5e1}a{color:#60a5fa;text-decoration:none}
details{margin-top:4px}summary{cursor:pointer;color:#94a3b8;font-size:12px}
.fix{color:#86efac;font-size:13px;margin-top:4px}.note{color:#fcd34d;font-size:12px;margin-top:4px}
.tag{display:inline-block;font-size:11px;padding:0 6px;border-radius:4px;background:#1f2937;color:#cbd5e1;margin-right:4px}
.new{color:#f87171}.ok{color:#4ade80}.chg{color:#fbbf24}ul{margin:6px 0;padding-left:20px}
"""


def _e(v: Any) -> str:
    return escape(str(v), quote=True)


def _badge(sev: str) -> str:
    return f'<span class="sev" lang="en" style="background:{_COLOR.get(sev, "#6b7280")}">{_e(sev)}</span>'


def _mitre(ids: list[str]) -> str:
    return " ".join(
        f'<a class="tag" href="https://attack.mitre.org/techniques/{_e(t.replace(".", "/"))}/" '
        f'rel="noopener noreferrer">{_e(t)}</a>' for t in ids)


def _cve_table(cves: list[dict]) -> str:
    rows = "".join(
        f"<tr><td><a href=\"https://nvd.nist.gov/vuln/detail/{_e(c.get('id', ''))}\" rel=\"noopener noreferrer\">"
        f"{_e(c.get('id', ''))}</a>{' <span class=tag>KEV</span>' if c.get('kev') else ''}</td>"
        f"<td>{_e(c.get('score') if c.get('score') is not None else '?')}</td>"
        f"<td>{_e(' '.join(str(c.get('description', '')).split()))}</td></tr>"
        for c in cves)
    return f"<table><thead><tr><th>CVE</th><th>CVSS</th><th>Açıklama</th></tr></thead><tbody>{rows}</tbody></table>"


def _finding_row(f: Finding) -> str:
    extra = ""
    if f.module == "vuln" and f.data.get("cves"):
        more = " (ilk 50)" if f.data.get("truncated") else ""
        extra += f"<details><summary>{len(f.data['cves'])} CVE{more}</summary>{_cve_table(f.data['cves'])}</details>"
    if f.data.get("note"):
        extra += f'<div class="note">⚠ {_e(f.data["note"])}</div>'
    if f.remediation:
        extra += f'<div class="fix">↳ {_e(f.remediation)}</div>'
    return (f"<tr><td>{_badge(f.severity)}</td><td><code>{_e(f.target)}</code><br>"
            f"<span class=muted>{_e(f.key)}</span></td><td>{_e(f.title)}{extra}</td>"
            f"<td>{_mitre(f.mitre)}</td></tr>")


def _findings_table(findings: list[Finding], hide_info: bool) -> str:
    shown = [f for f in findings if not (hide_info and f.severity == "info")]
    hidden = len(findings) - len(shown)
    body = "".join(_finding_row(f) for f in shown) or '<tr><td colspan="4" class="muted">Sorun yok.</td></tr>'
    table = ("<table><thead><tr><th>Önem</th><th>Hedef</th><th>Bulgu / düzeltme</th><th>ATT&amp;CK</th></tr>"
             f"</thead><tbody>{body}</tbody></table>")
    if hidden:
        info = [f for f in findings if f.severity == "info"]
        rows = "".join(f"<tr><td><code>{_e(f.target)}</code></td><td>{_e(f.title)}</td></tr>" for f in info)
        table += (f"<details><summary>{hidden} bilgi seviyesinde kayıt</summary>"
                  f"<table><tbody>{rows}</tbody></table></details>")
    return table


def _diff_section(d: DiffResult) -> str:
    def lst(items: list[Finding], cls: str, mark: str) -> str:
        if not items:
            return '<p class="muted">—</p>'
        return "<ul>" + "".join(
            f'<li class="{cls}">{mark} {_badge(f.severity)} <code>{_e(f.target)}</code> {_e(f.title)}</li>'
            for f in items) + "</ul>"

    changes = ""
    for c in d.changed:
        fields = "".join(f"<li><code>{_e(k)}</code>: {_e(_short(o))} → {_e(_short(n))}</li>"
                         for k, (o, n) in c.fields.items())
        changes += (f'<li class="chg">~ {_badge(c.new.severity)} <code>{_e(c.new.target)}</code> '
                    f"{_e(c.new.title)}<ul>{fields}</ul></li>")
    changes = f"<ul>{changes}</ul>" if changes else '<p class="muted">—</p>'
    return (f"<h2>Değişiklikler: tarama #{d.old_scan.id} → #{d.new_scan.id} "
            f"<span class=muted>({_e(d.new_scan.modules and ', '.join(d.new_scan.modules))})</span></h2>"
            f'<p class="muted">{_e(d.old_scan.started_at)} ile {_e(d.new_scan.started_at)} arası · '
            f"{d.unchanged} değişmeyen · {d.not_rescanned} tekrar taranmayan</p>"
            f"<h3 class=new>Yeni ({len(d.new)})</h3>{lst(d.new, 'new', '+')}"
            f"<h3 class=chg>Değişen ({len(d.changed)})</h3>{changes}"
            f"<h3 class=ok>Kapanan ({len(d.resolved)})</h3>{lst(d.resolved, 'ok', '−')}")


def _short(v: Any, n: int = 120) -> str:
    s = str(v)
    return s if len(s) <= n else s[: n - 3] + "..."


def render_html(scope_name: str, scans: list[tuple[ScanRecord, list[Finding]]],
                diffs: list[DiffResult], hide_info: bool = True) -> str:
    all_f = [f for _, fs in scans for f in fs]
    sev = Counter(f.severity for f in all_f)
    cards = [f'<div class="card"><div class="n">{len(all_f)}</div><div class="l">Bulgu</div></div>']
    for s in reversed(SEVERITIES):
        if sev.get(s):
            cards.append(f'<div class="card"><div class="n" style="color:{_COLOR[s]}">{sev[s]}</div>'
                         f'<div class="l" lang="en">{_e(s)}</div></div>')
    changes = sum(len(d.new) + len(d.changed) + len(d.resolved) for d in diffs)
    cards.append(f'<div class="card"><div class="n">{changes}</div><div class="l">Değişiklik</div></div>')

    # Öncelik listesi: kritik/yüksek bulgular (ilk 15)
    top = sorted((f for f in all_f if f.severity in ("critical", "high")),
                 key=lambda f: (-_ORDER[f.severity], f.module, f.target))[:15]
    top_html = ("<ol>" + "".join(f"<li>{_badge(f.severity)} <code>{_e(f.target)}</code> {_e(f.title)}</li>"
                                 for f in top) + "</ol>") if top else '<p class="muted">Kritik/yüksek bulgu yok.</p>'

    # MITRE kapsamı
    tech: dict[str, set[str]] = {}
    for f in all_f:
        if f.severity == "info":
            continue
        for t in f.mitre:
            tech.setdefault(t, set()).add(f.module)
    tech_rows = "".join(f"<tr><td>{_mitre([t])}</td><td>{_e(', '.join(sorted(m)))}</td></tr>"
                        for t, m in sorted(tech.items())) or '<tr><td colspan="2" class="muted">—</td></tr>'

    sections = ""
    for scan, findings in scans:
        mod = ", ".join(scan.modules)
        title = " / ".join(_MODULE_TITLE.get(m, m) for m in scan.modules)
        ordered = sorted(findings, key=lambda f: (-_ORDER[f.severity], f.target, f.key))
        sections += (f"<h2>{_e(title)}</h2><p class=muted>Tarama #{scan.id} · {_e(mod)} · "
                     f"{_e(scan.started_at)} · hedefler: {_e(', '.join(scan.targets[:10]))}"
                     f"{' …' if len(scan.targets) > 10 else ''}</p>{_findings_table(ordered, hide_info)}")

    diff_html = "".join(_diff_section(d) for d in diffs)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!DOCTYPE html>
<html lang="tr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="referrer" content="no-referrer">
<title>SurfaceWatch raporu: {_e(scope_name)}</title><style>{_CSS}</style></head>
<body><main>
<h1>SurfaceWatch raporu</h1>
<div class="muted">Kapsam: <b>{_e(scope_name)}</b> · {_e(generated)} · v{_e(__version__)}</div>
<div class="cards">{''.join(cards)}</div>
<h2>Öncelikli bulgular</h2>{top_html}
{diff_html}
{sections}
<h2>MITRE ATT&amp;CK eşlemesi</h2>
<p class="muted">Bilgi seviyesi hariç bulgularda görülen teknikler.</p>
<table><thead><tr><th>Teknik</th><th>Modül</th></tr></thead><tbody>{tech_rows}</tbody></table>
<h2>Yöntem ve sınırlamalar</h2>
<ul class="muted">
<li>Sadece kapsam dosyasında tanımlı hedefler tarandı; aktif taramalarda IP sabitlendi.</li>
<li>CVE eşleşmeleri sürüm tabanlıdır; dağıtım backport'ları nedeniyle yanlış pozitif olabilir.</li>
<li>Web kontrolleri yapılandırma odaklıdır; uygulama mantığı (XSS, SQLi vb.) test edilmedi.</li>
<li>Bu rapor yetkili bir değerlendirme için üretilmiştir.</li>
</ul>
</main></body></html>
"""
