import requests
import sys


def main(args):
    if args[0] == "health":
        print("healthy", end="")
        return

    teamIp, newFlag = args

    print(teamIp, newFlag)


if __name__ == "__main__":
    main(sys.argv[1:])
