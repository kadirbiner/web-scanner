from core.runner import run_command

async def run_ffuf(target: str):
    wordlist = "/usr/share/wordlists/dirb/common.txt"
    clean_target = target.rstrip("/")

    command = [
        "ffuf",
        "-u", f"{clean_target}/FUZZ",
        "-w", wordlist,
        "-mc", "200,301,302,403",
        "-json"
    ]

    return await run_command(command, timeout=120)