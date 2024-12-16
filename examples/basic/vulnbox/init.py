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

    with open("/etc/init.d/app", "w") as f:
        f.write(
            """#!/sbin/openrc-run
command="/usr/bin/python3"
command_args="/root/app.py"
command_background="yes"
pidfile="/run/app.pid"
respawn="yes"
respawn_delay="5"
# Set the working directory to the directory of the script
directory="/root"
"""
        )

    os.chmod("/etc/init.d/app", 0o755)

    subprocess.check_call(
        ["service", "app", "start"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    time.sleep(1)

    # Check if the service is running
    response = subprocess.run(
        ["service", "app", "status"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    if response.returncode != 0:
        print("error", response.stderr)
        return

    # Request the homepage of the service
    response = subprocess.run(
        ["curl", f"http://{teamIp}:5000/"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if response.returncode != 0:
        print("error", response.stderr)
        return

    print("success")


if __name__ == "__main__":
    import sys

    main(sys.argv[1:])
