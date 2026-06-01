from core.runner import run_command
from config import WORDLISTS


async def run_ffuf(context, mode: str = "small"):
    clean_target = context.target.rstrip("/")
    wordlist = WORDLISTS.get(mode, WORDLISTS["small"])

    command = [
        "ffuf",
        "-u", f"{clean_target}/FUZZ",
        "-w", wordlist,
        "-mc", "200,204,301,302,307,401,403",
        "-t", "20",
        "-rate", "50",
        "-json"
    ]

    result = await run_command(command, timeout=300)
    context.raw["ffuf"] = result

    return context