from core.runner import run_command
from config import WORDLISTS, COMMON_EXTENSIONS

async def run_ffuf(context, mode: str = "small"):
    clean_target = context.target.rstrip("/")
    wordlist = WORDLISTS.get(mode, WORDLISTS["small"])
    extensions = ",".join(COMMON_EXTENSIONS)

    command = [
        "ffuf",
        "-u", f"{clean_target}/FUZZ",
        "-w", wordlist,
        "-e", extensions,
        "-mc", "200,204,301,302,307,401,403",
        "-ac",
        "-json"
    ]

    result = await run_command(command, timeout=180)

    context.raw["ffuf"] = result

    return context