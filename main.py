import asyncio
import typer

from rich.panel import Panel
from rich.console import Console
from rich.table import Table

from config import ALLOWED_SCHEMES
from core.dependency_check import check_dependencies
from core.orchestrator import start_scan
from parsers.ffuf_parser import parse_ffuf_output
from utils.logger import error, warning, success

app = typer.Typer()
console = Console()

def validate_target(target: str):
    if not any(target.startswith(scheme) for scheme in ALLOWED_SCHEMES):
        error("Hedef http:// veya https:// ile başlamalı.")
        raise typer.Exit()

@app.callback(invoke_without_command=True)
def main(target: str = typer.Argument(None)):
    if target is None:
        console.print("Kullanım:")
        console.print("python main.py http://pastezone.hv/")
        raise typer.Exit()

    console.print(Panel.fit(
        "[bold cyan]Automated CTF Web Scanner[/bold cyan]\nLab/CTF kullanımı içindir.",
        border_style="cyan"
    ))

    validate_target(target)

    missing = check_dependencies()

    if missing:
        warning("Bazı araçlar eksik:")
        for tool in missing:
            console.print(f"- {tool}")
        raise typer.Exit()

    results = asyncio.run(start_scan(target))

    console.print("\n[bold green]HTTPX Çıktısı[/bold green]")
    console.print(results["httpx"]["stdout"] or results["httpx"]["stderr"])

    console.print("\n[bold green]WhatWeb Çıktısı[/bold green]")
    console.print(results["whatweb"]["stdout"] or results["whatweb"]["stderr"])

    console.print("\n[bold green]Nmap Çıktısı[/bold green]")
    console.print(results["nmap"]["stdout"] or results["nmap"]["stderr"])

    console.print("\n[bold green]FFUF Bulguları[/bold green]")

    ffuf_findings = parse_ffuf_output(results["ffuf"]["stdout"])

    table = Table(title="FFUF Bulguları")
    table.add_column("Status", style="cyan")
    table.add_column("URL", style="green")
    table.add_column("Length", style="yellow")
    table.add_column("Redirect", style="magenta")

    for item in ffuf_findings:
        table.add_row(
            str(item["status"]),
            str(item["url"]),
            str(item["length"]),
            str(item["redirect"])
        )

    console.print(table)

    success("Tarama başarıyla tamamlandı.")

if __name__ == "__main__":
    app()