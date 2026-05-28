from core.runner import run_command

async def run_nmap(target: str):
    clean_target = target.replace("http://", "").replace("https://", "").split("/")[0]

    command = [
        "nmap",
        "-sV",
        "-T3",
        clean_target
    ]

    return await run_command(command, timeout=120)