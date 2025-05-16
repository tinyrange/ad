#!/usr/bin/env python3

from pwn import remote, context
from typing import Union, Optional, Callable
import re
import requests
import sqlite3
import sys

game_server = "10.40.0.1"
flag_submission_port = 5000

flag_regex = re.compile(r"flag\{[a-zA-Z0-9_\-\.]*\}")

PERSISTENCE_DB = "libad.db"

_has_initd_db = False

def get_db():
    global _has_initd_db
    db = sqlite3.connect(PERSISTENCE_DB)
    if not _has_initd_db:
        init_db(db)
        _has_initd_db = True
    return db

def init_db(db):
    # The `flag_id` column is nullable, otherwise it would be the primary key.
    db.execute("""
        CREATE TABLE IF NOT EXISTS submitted_flags (
            flag TEXT PRIMARY KEY,
            flag_id TEXT,
            tick_id INTEGER,
            team_id INTEGER,
            service_id INTEGER,
            response TEXT
        )
        """)
    db.commit()

class FlagId:
    tick: int
    team: int
    service: int
    value: str

    def __init__(self, tick: int, team: int, service: int, value: str):
        self.tick = tick
        self.team = team
        self.service = service
        self.value = value

    def __repr__(self) -> str:
        return self.value

def cache_flag_response(flag: str, flag_id: Optional[FlagId], response: str):
    db = get_db()
    tick_id, team_id, service_id = map(int, flag[5:].split(".")[:3])
    db.execute(
        """
        INSERT INTO submitted_flags (
            flag, flag_id, tick_id, team_id, service_id, response
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        [
            flag, None if flag_id is None else flag_id.value,
            tick_id, team_id, service_id, response
        ]
    )
    db.commit()
    db.close()

def flag_id_has_been_captured(flag_id: FlagId) -> bool:
    db = get_db()
    result = db.execute(
        "SELECT * FROM submitted_flags WHERE flag_id=? AND response='FLAG_ACCEPTED'",
        [flag_id.value]
    )
    captured = result.fetchone() is not None
    db.close()
    return captured

def cached_flag_response(flag: str) -> Optional[str]:
    db = get_db()
    result = db.execute("SELECT response FROM submitted_flags WHERE flag=?", [flag])
    response = result.fetchone()
    db.close()
    return None if response is None else response[0]

# If present, `flag_id` gets cached in addition to the flag and helps libad
# avoid running your exploit against the same flag id twice. If not, only the
# flag is cached.
def submit_flag(flag: str, flag_id: Optional[FlagId] = None) -> str:
    if (response := cached_flag_response(flag) is not None):
        return "FLAG_ALREADY_STOLEN" if response == "FLAG_ACCEPTED" else response

    tmp = context.log_level
    context.log_level = "warn"
    p = remote(game_server, flag_submission_port)

    p.sendline(flag.encode())
    response = p.recvline().decode().strip()
    p.close()
    context.log_level = tmp

    cache_flag_response(flag, flag_id, response)

    return response

def extract_flags(content: str) -> list[str]:
    return [match for match in flag_regex.findall(content)]

def extract_flag(content: str) -> Optional[str]:
    flags = flag_regex.findall(content)
    if len(flags) == 0:
        raise Exception(f"No flag found in '{content}'")
    return flags[0]

class Team:
    id: int
    name: str
    ip: str
    is_self: bool

    def __init__(self, id: int, name: str, ip: str, is_self: bool):
        self.id = id
        self.name = name
        self.ip = ip
        self.is_self = is_self

class TeamStore:
    teams: list[Team]

    def __init__(self, teams: list[Team]):
        self.teams = teams

    # Finds a team by id or name. Names are case insensitive.
    def team(self, identifier: Union[int, str]) -> Optional[Team]:
        for team in self.teams:
            if type(identifier) == int and team.id == identifier:
                return team
            elif type(identifier) == str and team.name.lower() == identifier.lower():
                return team
        return None

_teams: Optional[TeamStore] = None

def fetch_teams() -> TeamStore:
    global _teams
    response = requests.get(f"http://{game_server}/api/teams")
    data = response.json()
    store = TeamStore([
        Team(team["id"], team["name"], team["ip"], team["self"])
        for team in data
    ])
    _teams = store
    return store

# Finds a team by id or name. Names are case insensitive.
def get_team(identifier: Union[int, str]) -> Optional[Team]:
    if _teams is None:
        fetch_teams()
    return _teams.team(identifier)

class Service:
    id: int
    name: str
    port: int

    def __init__(self, id: int, name: str, port: int):
        self.id = id
        self.name = name
        self.port = port

class ServiceStore:
    services: list[Service]

    def __init__(self, services: list[Service]):
        self.services = services

    # Finds a service by id or name. Names are case insensitive.
    def service(self, identifier: Union[int, str]) -> Optional[Service]:
        for service in self.services:
            if type(identifier) == int and service.id == identifier:
                return service
            elif type(identifier) == str and service.name.lower() == identifier.lower():
                return service
        return None

_services: Optional[ServiceStore] = None

def fetch_services() -> ServiceStore:
    global _services
    response = requests.get(f"http://{game_server}/api/vulnbox/services")
    data = response.json()
    store = ServiceStore([
        Service(service["id"], service["name"], service["port"])
        for service in data
    ])
    _services = store
    return store

# Finds a service by id or name. Names are case insensitive.
def get_service(identifier: Union[int, str]) -> Optional[Team]:
    if _services is None:
        fetch_services()
    return _services.service(identifier)

class FlagIdStore:
    _flag_ids: list[FlagId]

    def __init__(self, flag_ids: list[FlagId]):
        self._flag_ids = flag_ids

    # Find all flag ids matching the given criteria. `team` and `service` can
    # be either ids or names. Names are case insensitive.
    def flag_ids(self, tick: int = None, team: Union[int, str] = None, service: Union[int, str] = None, skip_self: bool = False) -> list[FlagId]:
        if _teams is None and (type(team) == str or skip_self):
            fetch_teams()
        if type(team) == str:
            team = _teams.team(team).id

        if type(service) == str:
            if _services is None:
                fetch_services()
            service = _services.service(service).id

        filtered = []
        for flag_id in self._flag_ids:
            if tick is not None and tick != flag_id.tick:
                continue
            if team is not None and team != flag_id.team:
                continue
            if service is not None and service != flag_id.service:
                continue
            if skip_self and _teams.team(flag_id.team).is_self:
                continue
            filtered.append(flag_id)
        return filtered

def fetch_flag_ids() -> FlagIdStore:
    response = requests.get(f"http://{game_server}/api/flagIds")
    data = response.json()

    flag_ids = []
    for flag_id in data:
        flag_ids.append(FlagId(
            flag_id["tick"],
            flag_id["team"],
            flag_id["service"],
            flag_id["value"]
        ))

    return FlagIdStore(flag_ids)

# Find all flag ids matching the given criteria. `team` and `service` can
# be either ids or names. Names are case insensitive. Shorthand for fetching
# then filtering. Doesn't cache.
def get_flag_ids(
    tick: int = None, team: Union[int, str] = None,
    service: Union[int, str] = None, skip_self: bool = False
) -> list[FlagId]:
    flag_ids = fetch_flag_ids()
    return flag_ids.flag_ids(tick=tick, team=team, service=service, skip_self=skip_self)

# Returns the number of new flags captured.
def run_exploit(
    exploit: Callable[tuple[str, FlagId], str],
    service: Union[int, str],
    teams: Optional[list[Union[int, str]]] = None
) -> int:
    if teams is None:
        teams = [team.id for team in fetch_teams().teams if not team.is_self]

    service = get_service(service)
    for team in teams:
        flag_ids = get_flag_ids(team=team, service=service.id)
        team = get_team(team)
        count = 0
        for flag_id in flag_ids:
            if flag_id_has_been_captured(flag_id):
                continue
            address = f"{team.ip}:{service.port}"
            count += 1
            try:
                flag = exploit(address, flag_id)
                response = submit_flag(flag, flag_id=flag_id)
                print(f"({flag_id}/tick {flag_id.tick}/team {flag_id.team}/service {flag_id.service}) {response}")
            except KeyboardInterrupt:
                exit(1)
            except Exception as e:
                print(f"Failed to run exploit: {e}")
    if count == 0:
        print("No new flags")
    return count

def _usage():
    print("Usage: ./libad.py <command> <args ...>")
    print("Commands: [submit]")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        _usage()
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
        _usage()
        exit(1)
