from rich.console import Console

console = Console()

def info(message: str):
    console.print(f"[cyan][INFO][/cyan] {message}")

def success(message: str):
    console.print(f"[green][OK][/green] {message}")

def warning(message: str):
    console.print(f"[yellow][WARN][/yellow] {message}")

def error(message: str):
    console.print(f"[red][ERROR][/red] {message}")