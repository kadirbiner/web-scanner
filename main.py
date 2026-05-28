import asyncio
import typer
from rich.panel import Panel
from rich.console import Console

from config import ALLOWED_SCHEMES
from core.dependency_check import check_dependencies
from core.orchestrator import start_scan
from utils.logger import error, warning, success

app = typer.Typer()
console = Console()

def validate_target(target: str):
    if not any(target.startswith(scheme) for scheme in ALLOWED_SCHEMES):
        error("Hedef http:// veya https:// ile başlamalı.")
        raise typer.Exit()

@app.command()
def scan(target: str):
    """
    Lab/CTF ortamı için web keşif taraması başlatır.
    """

    console.print(Panel.fit(
        "[bold cyan]Automated CTF Web Scanner[/bold cyan]\nLab/CTF kullanımı içindir.",
        border_style="cyan"
    ))

    validate_target(target)

    missing = check_dependencies()

    if missing:
        warning("Bazı araçlar eksik. Eksik araçlar:")
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

    success("İlk sürüm başarıyla çalıştı.")

if __name__ == "__main__":
    app()