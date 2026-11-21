"""SurfaceWatch CLI.

    surfacewatch init                     scope.yml şablonu oluştur
    surfacewatch scope show               kapsamı göster
    surfacewatch scope check <hedef>      hedef taranabilir mi?
    surfacewatch scans                    geçmiş taramalar

scan (red) ve watch (blue) komutları sonraki modüllerde eklenecek.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .core import Scope, ScopeError, Storage

SCOPE_TEMPLATE = """\
# SurfaceWatch kapsam dosyası
# Burada olmayan hiçbir hedef taranmaz. Sadece sahibi olduğun ya da
# yazılı izin aldığın sistemleri ekle.

name: home-lab

targets:
  networks:
    - 192.168.56.0/24        # VirtualBox host-only ağı (kendininkine göre düzenle)
  hosts: []                  # tek IP'ler, ör. 10.10.10.5
  domains: []
    # - name: ornek-domainim.com
    #   include_subdomains: true

exclude:
  - 192.168.56.1             # host makinenin kendisi / gateway

options:
  # Kapsamdaki bir domain kapsam dışı bir IP'ye çözülürse (CDN, SaaS)
  # aktif tarama reddedilir. Bunu kapatmak bilinçli bir karar olmalı.
  allow_unscoped_resolution: false
"""


def _load_scope(args: argparse.Namespace) -> Scope:
    return Scope.load(Path(args.scope))


def cmd_init(args: argparse.Namespace) -> int:
    path = Path(args.scope)
    if path.exists() and not args.force:
        print(f"[!] {path} zaten var (üzerine yazmak için --force)", file=sys.stderr)
        return 2
    path.write_text(SCOPE_TEMPLATE, encoding="utf-8")
    print(f"[+] {path} oluşturuldu. Hedeflerini düzenle, sonra: surfacewatch scope show")
    return 0


def cmd_scope_show(args: argparse.Namespace) -> int:
    s = _load_scope(args)
    print(f"Kapsam: {s.name}")
    for n in s.networks:
        print(f"  + ağ     {n}  ({n.num_addresses} adres)")
    for d in s.domains:
        print(f"  + domain {d.name}{'  (+ alt alan adları)' if d.include_subdomains else ''}")
    for n in s.exclude_networks:
        print(f"  - hariç  {n}")
    for d in s.exclude_domains:
        print(f"  - hariç  {d.name}")
    print(f"  çözümlenen IP kontrolü: {'KAPALI' if s.allow_unscoped_resolution else 'açık'}")
    return 0


def cmd_scope_check(args: argparse.Namespace) -> int:
    s = _load_scope(args)
    color = sys.stdout.isatty()
    worst = 0
    for target in args.targets:
        d = s.check(target, active=not args.passive)
        label = "İZİN" if d.allowed else "RED "
        if color:
            label = f"\033[{'32' if d.allowed else '31'}m{label}\033[0m"
        extra = f"  [{', '.join(d.resolved)}]" if d.resolved else ""
        print(f"{label}  {d.target:<35} {d.reason}{extra}")
        if not d.allowed:
            worst = 1
    return worst


def cmd_scans(args: argparse.Namespace) -> int:
    with Storage(args.db) as db:
        scans = db.list_scans(limit=args.limit)
    if not scans:
        print("Henüz tarama yok.")
        return 0
    print(f"{'ID':>4}  {'KAPSAM':<14} {'BAŞLANGIÇ':<26} {'DURUM':<8} MODÜLLER")
    for sc in scans:
        print(f"{sc.id:>4}  {sc.scope_name:<14} {sc.started_at:<26} {sc.status:<8} {','.join(sc.modules)}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="surfacewatch",
                                description="Kapsam kontrollü saldırı yüzeyi tarama ve izleme")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("-s", "--scope", default="scope.yml", help="Kapsam dosyası (varsayılan: scope.yml)")
    p.add_argument("--db", default="surfacewatch.db", help="SQLite veritabanı")
    sub = p.add_subparsers(dest="command", required=True)

    i = sub.add_parser("init", help="scope.yml şablonu oluştur")
    i.add_argument("--force", action="store_true")
    i.set_defaults(func=cmd_init)

    sc = sub.add_parser("scope", help="Kapsam işlemleri")
    scsub = sc.add_subparsers(dest="scope_cmd", required=True)
    show = scsub.add_parser("show", help="Kapsamı göster")
    show.set_defaults(func=cmd_scope_show)
    chk = scsub.add_parser("check", help="Hedef(ler) taranabilir mi?")
    chk.add_argument("targets", nargs="+")
    chk.add_argument("--passive", action="store_true",
                     help="Pasif işlem kontrolü (DNS çözümlemesi gerektirmez)")
    chk.set_defaults(func=cmd_scope_check)

    ls = sub.add_parser("scans", help="Geçmiş taramaları listele")
    ls.add_argument("--limit", type=int, default=20)
    ls.set_defaults(func=cmd_scans)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ScopeError as exc:
        print(f"[!] Kapsam hatası: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
