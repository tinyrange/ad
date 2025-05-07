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

    services = [
        ("pastebin", 5000, "/usr/bin/python3", "/root/pastebin/app.py", True),
        ("post_office", 5001, "/usr/bin/python3", "/root/post_office/app.py", True),
        ("pcap-broker", 4242, "/root/pcap-broker/pcap-broker", "-cmd \\\"tcpdump -i eth0 -n --immediate-mode -s 65535 -U -w - '! (dst 10.42.0.2 and (dst port 2222 or dst port 4242)) and ! (src 10.42.0.2 and (src port 2222 or src port 4242))'\\\" -listen 0.0.0.0:4242", False),
    ]

    for service, port, cmd, args, check in services:
        with open(f"/etc/init.d/{service}", "w") as f:
            f.write(
                f"""#!/sbin/openrc-run
command="{cmd}"
command_args="{args}"
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

        if check:
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
