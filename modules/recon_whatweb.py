from core.runner import run_command

async def run_whatweb(context):
    command = [
        "whatweb",
        context.target
    ]

    result = await run_command(command, timeout=60)
    context.technologies = result["stdout"] or result["stderr"]
    context.raw["whatweb"] = result

    return context