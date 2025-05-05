#!/usr/bin/env python3

import subprocess
import json
import os
import time


def main(args):
    teamIp, teamName = args

    with open("data.json", "w") as f:
        json.dump({"team": {"name": teamName, "ip": teamIp}}, f)

    subprocess.check_call(
        ["openrc"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    subprocess.check_call(["touch", "/run/openrc/softlevel"])

    services = [("pastebin", 5000), ("post_office", 5001)]

    for service, port in services:
        with open(f"/etc/init.d/{service}", "w") as f:
            f.write(
                f"""#!/sbin/openrc-run
command="/usr/bin/python3"
command_args="/root/{service}/app.py"
command_background="yes"
pidfile="/run/{service}.pid"
respawn="yes"
respawn_delay="5"
# Set the working directory to the directory of the script
directory="/root/{service}"
"""
            )

        os.chmod(f"/etc/init.d/{service}", 0o755)

        subprocess.check_call(
            ["service", service, "start"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        time.sleep(1)

        # Check if the service is running
        response = subprocess.run(
            ["service", service, "status"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        if response.returncode != 0:
            print(f"error: {service}:", response.stderr)
            return

        # Request the homepage of the service
        response = subprocess.run(
            ["curl", f"http://{teamIp}:{port}/"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if response.returncode != 0:
            print(f"error: {service}:", response.stderr)
            return
    print("success")


if __name__ == "__main__":
    import sys

    main(sys.argv[1:])
