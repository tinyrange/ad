#!/usr/bin/env python3

from pwn import remote, context
import sys

game_server = "10.40.0.1"
flag_submission_port = 5000

def submit_flag(flag: str) -> str:
    tmp = context.log_level
    context.log_level = "warn"
    p = remote(game_server, flag_submission_port)

    p.sendline(flag.encode())
    response = p.recvline().decode().strip()
    p.close()
    context.log_level = tmp

    return response

def usage():
    print("Usage: ./libad.py <command> <args ...>")
    print("Commands: [submit]")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()
        exit(1)

    cmd = sys.argv[1]
    if cmd == "submit":
        if len(sys.argv) < 3:
            print("Usage: ./libad.py submit [flag ...]")
            exit(1)
        flags = sys.argv[2:]
        for flag in flags:
            print(submit_flag(flag))
    else:
        usage()
        exit(1)
