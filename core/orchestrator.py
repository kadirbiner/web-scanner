import asyncio

from core.models import ScanContext
from utils.logger import info, success

from modules.recon_headers import run_header_recon
from modules.recon_nmap import run_nmap
from modules.recon_whatweb import run_whatweb
from modules.discovery_robots import run_robots_discovery
from modules.discovery_ffuf import run_ffuf
from modules.passive_analyzer import run_passive_analysis
from modules.safe_signals import run_safe_signals

async def start_scan(target: str, ffuf_mode: str = "small"):
    context = ScanContext(target=target)

    info("Recon başlatıldı.")
    context = run_header_recon(context)
    context = run_robots_discovery(context)

    recon_tasks = [
        run_nmap(context),
        run_whatweb(context),
        run_ffuf(context, mode=ffuf_mode)
    ]

    await asyncio.gather(*recon_tasks)

    success("Recon ve discovery tamamlandı.")

    info("Passive analysis başlatıldı.")
    context = run_passive_analysis(context)

    info("Safe vuln signals başlatıldı.")
    context = run_safe_signals(context)

    success("Tarama tamamlandı.")

    return context