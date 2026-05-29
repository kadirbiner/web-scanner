import asyncio

from modules.httpx_scan import run_httpx
from modules.whatweb_scan import run_whatweb
from modules.nmap_scan import run_nmap
from modules.ffuf_scan import run_ffuf

from utils.logger import info, success

async def start_scan(target: str):
    info(f"Tarama başlatıldı: {target}")

    tasks = [
        run_httpx(target),
        run_whatweb(target),
        run_nmap(target),
        run_ffuf(target)
    ]

    results = await asyncio.gather(*tasks)

    success("Tarama tamamlandı.")

    return {
        "httpx": results[0],
        "whatweb": results[1],
        "nmap": results[2],
        "ffuf": results[3]
    }