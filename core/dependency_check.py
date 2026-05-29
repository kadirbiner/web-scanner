import shutil
from config import REQUIRED_TOOLS
from utils.logger import success, warning

def check_dependencies():
    missing = []

    for tool in REQUIRED_TOOLS:
        if shutil.which(tool):
            success(f"{tool} bulundu.")
        else:
            warning(f"{tool} bulunamadı.")
            missing.append(tool)

    return missing