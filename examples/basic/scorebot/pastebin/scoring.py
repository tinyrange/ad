import requests
import sys
import json
import hashlib


def write_out(data):
    print(json.dumps(data), end="")
    sys.stdout.flush()

def write_success():
    write_out({"status": "success"})

def write_error(message):
    write_out({"status": "error", "message": message})

def main(args):
    if args[0] == "health":
        print("healthy", end="")
        return

    teamIp, newFlag, flagId, servicePort = args

    # Make a paste with the new flag
    password = hashlib.sha512(newFlag.encode()).hexdigest()[:12]
    response = requests.post(
        f"http://{teamIp}:{servicePort}/paste",
        data={"id": flagId, "content": newFlag, "password": password}
    )

    # Check if the paste was successful
    if response.status_code != 200:
        write_error(f"Failed to create paste: {response.text}")
        return

    # Get the paste content
    response = requests.post(
        f"http://{teamIp}:{servicePort}/paste/{flagId}",
        data={"password": password}
    )

    # Check if the paste was found
    if response.status_code != 200:
        write_error(f"Failed to get paste: {response.text}")
        return

    # Check if the paste content is the same as the new flag
    if newFlag not in response.text:
        write_error("Flag mismatch")
        return

    write_success()


if __name__ == "__main__":
    main(sys.argv[1:])
