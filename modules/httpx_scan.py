from core.runner import run_command
import shutil

async def run_httpx(target: str):
    httpx_path = shutil.which("httpx")

    command = [
        httpx_path,
        target
    ]

    return await run_command(command, timeout=60)