import asyncio
import typer
import urllib3

from rich.panel import Panel
from rich.console import Console
from rich.table import Table

from config import ALLOWED_SCHEMES
from core.dependency_check import check_dependencies
from core.orchestrator import start_scan
from core.findings import sort_findings
from utils.logger import error, warning, success

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = typer.Typer()
console = Console()


def validate_target(target: str):
    if not any(target.startswith(scheme) for scheme in ALLOWED_SCHEMES):
        error("Hedef http:// veya https:// ile başlamalı.")
        raise typer.Exit()


def print_recon_summary(context):
    console.print("\n[bold cyan]Recon Özeti[/bold cyan]")

    table = Table(title="Recon Summary")
    table.add_column("Alan", style="cyan")
    table.add_column("Değer", style="green")

    table.add_row("Target", context.target)
    table.add_row("Homepage Status", str(context.raw.get("homepage_status", "N/A")))
    table.add_row("Header Count", str(len(context.headers)))
    table.add_row("Links Found", str(len(context.links)))
    table.add_row("Forms Found", str(len(context.forms)))
    table.add_row("Params Found", str(len(context.params)))
    table.add_row("Crawled Pages", str(len(context.crawled_pages)))
    table.add_row("FFUF Findings", str(len(context.ffuf_findings)))

    console.print(table)


def print_crawler(context):
    console.print("\n[bold cyan]Crawler Engine[/bold cyan]")

    table = Table(title="Crawled Pages")
    table.add_column("Status", style="cyan")
    table.add_column("Depth", style="yellow")
    table.add_column("URL", style="green")
    table.add_column("Links", style="magenta")
    table.add_column("Forms", style="blue")
    table.add_column("Params", style="red")

    for page in context.crawled_pages:
        table.add_row(
            str(page.get("status", "")),
            str(page.get("depth", "")),
            str(page.get("url", "")),
            str(page.get("links_found", "")),
            str(page.get("forms_found", "")),
            str(page.get("params_found", ""))
        )

    console.print(table)


def print_ffuf(context):
    console.print("\n[bold cyan]Discovery / FFUF[/bold cyan]")

    table = Table(title="FFUF Findings")
    table.add_column("Status", style="cyan")
    table.add_column("URL", style="green")
    table.add_column("Length", style="yellow")
    table.add_column("Redirect", style="magenta")

    for item in context.ffuf_findings:
        table.add_row(
            str(item.get("status", "")),
            str(item.get("url", "")),
            str(item.get("length", "")),
            str(item.get("redirect", ""))
        )

    console.print(table)


def print_findings(context):
    console.print("\n[bold red]Findings Engine[/bold red]")

    table = Table(title="Security Findings")
    table.add_column("Severity", style="red")
    table.add_column("Title", style="cyan")
    table.add_column("URL", style="green")
    table.add_column("Evidence", style="yellow")
    table.add_column("Source", style="magenta")

    for finding in sort_findings(context.findings):
        table.add_row(
            finding.severity,
            finding.title,
            finding.url,
            finding.evidence,
            finding.source
        )

    console.print(table)


def print_raw(context):
    console.print("\n[bold cyan]Nmap Çıktısı[/bold cyan]")
    console.print(context.ports or "Nmap çıktısı yok.")

    console.print("\n[bold cyan]WhatWeb Çıktısı[/bold cyan]")
    console.print(context.technologies or "WhatWeb çıktısı yok.")


@app.callback(invoke_without_command=True)
def main(
    target: str = typer.Argument(None),
    mode: str = typer.Option("small", help="FFUF wordlist modu: small, medium, raft"),
    show_raw: bool = typer.Option(False, help="Nmap ve WhatWeb ham çıktısını gösterir.")
):
    if target is None:
        console.print("Kullanım:")
        console.print("python main.py http://target.local")
        raise typer.Exit()

    console.print(Panel.fit(
        "[bold cyan]Automated CTF Web Scanner V2[/bold cyan]\nRecon + Discovery + Crawler + Passive Analysis + Safe Signals",
        border_style="cyan"
    ))

    validate_target(target)

    missing = check_dependencies()

    if missing:
        warning("Eksik araçlar var:")
        for tool in missing:
            console.print(f"- {tool}")
        raise typer.Exit()

    context = asyncio.run(start_scan(target, ffuf_mode=mode))

    print_recon_summary(context)
    print_crawler(context)
    print_ffuf(context)
    print_findings(context)

    if show_raw:
        print_raw(context)

    success("Scanner V2 başarıyla tamamlandı.")


if __name__ == "__main__":
    app()