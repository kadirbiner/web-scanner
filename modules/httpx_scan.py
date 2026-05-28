from core.runner import run_command

async def run_httpx(target: str):
    command = [
        "httpx",
        "-u", target,
        "-json",
        "-silent"
    ]

    return await run_command(command, timeout=60)