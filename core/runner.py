import asyncio
from utils.logger import error

async def run_command(command: list[str], timeout: int = 120):
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout
        )

        return {
            "command": " ".join(command),
            "returncode": process.returncode,
            "stdout": stdout.decode(errors="ignore"),
            "stderr": stderr.decode(errors="ignore")
        }

    except asyncio.TimeoutError:
        error(f"Komut timeout oldu: {' '.join(command)}")
        return {
            "command": " ".join(command),
            "returncode": -1,
            "stdout": "",
            "stderr": "Timeout"
        }

    except Exception as e:
        error(f"Komut çalıştırma hatası: {e}")
        return {
            "command": " ".join(command),
            "returncode": -1,
            "stdout": "",
            "stderr": str(e)
        }