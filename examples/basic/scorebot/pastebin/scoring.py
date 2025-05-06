import requests
import sys
import json


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

    teamIp, newFlag, servicePort = args

    # Make a paste with the new flag
    response = requests.post(f"http://{teamIp}:{servicePort}/api/paste", data={"content": newFlag})

    # Check if the paste was successful
    if response.status_code != 200:
        write_error("Failed to create paste")
        return

    # Get the paste ID
    pasteId = response.json()["id"]

    # Get the paste content
    response = requests.get(f"http://{teamIp}:{servicePort}/api/paste/{pasteId}")

    # Check if the paste was found
    if response.status_code != 200:
        write_error("Failed to get paste")
        return

    # Check if the paste content is the same as the new flag
    if response.json()["content"] != newFlag:
        write_error("Flag mismatch")
        return

    write_success()


if __name__ == "__main__":
    main(sys.argv[1:])
