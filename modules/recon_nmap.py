from core.runner import run_command
from utils.url_utils import get_hostname

async def run_nmap(context):
    host = get_hostname(context.target)

    command = [
        "nmap",
        "-Pn",
        "-sV",
        "-T3",
        host
    ]

    result = await run_command(command, timeout=120)
    context.ports = result["stdout"] or result["stderr"]
    context.raw["nmap"] = result

    return context