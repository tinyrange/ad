import requests
import sys


def main(args):
    teamIp, newFlag = args

    print(teamIp, newFlag)


if __name__ == "__main__":
    main(sys.argv[1:])
