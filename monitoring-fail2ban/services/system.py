import psutil
import platform
import subprocess

def get_server_info():

    cpu = psutil.cpu_percent(interval=1)

    ram = psutil.virtual_memory()

    disk = psutil.disk_usage("/")

    uptime = subprocess.getoutput("uptime -p")

    return {
        "hostname": platform.node(),
        "system": platform.system(),
        "release": platform.release(),
        "cpu": cpu,
        "ram": ram.percent,
        "disk": disk.percent,
        "uptime": uptime
    }
