from core.runner import run_command

async def run_whatweb(target: str):
    command = [
        "whatweb",
        target
    ]

    return await run_command(command, timeout=60)