from datetime import datetime
from log_parser import parse_line

FAIL = "Jan 15 02:31:07 labvm sshd[1234]: Failed password for bob from 10.0.0.5 port 51234 ssh2"
INVALID = "Jan 15 02:31:09 labvm sshd[1235]: Failed password for invalid user admin from 10.0.0.5 port 51236 ssh2"
OK = "Jan  5 09:05:00 labvm sshd[1300]: Accepted password for alice from 192.168.1.10 port 40022 ssh2"
NOISE = "Jan 15 02:32:00 labvm CRON[99]: pam_unix(cron:session): session opened for user root"


def test_failed_login():
    e = parse_line(FAIL, 2025)
    assert e["timestamp"] == datetime(2025, 1, 15, 2, 31, 7)
    assert e["username"] == "bob"
    assert e["source_ip"] == "10.0.0.5"
    assert e["source_port"] == "51234"
    assert e["status"] == "FAILURE"
    assert e["event_type"] == "LOGIN"
    assert e["device_id"] == "labvm"


def test_invalid_user():
    e = parse_line(INVALID, 2025)
    assert e["username"] == "admin"
    assert e["status"] == "FAILURE"


def test_accepted_login_single_digit_day():
    e = parse_line(OK, 2025)
    assert e["timestamp"] == datetime(2025, 1, 5, 9, 5, 0)
    assert e["status"] == "SUCCESS"
    assert e["username"] == "alice"


def test_unsupported_and_bad_lines():
    assert parse_line(NOISE, 2025) is None
    assert parse_line("garbage", 2025) is None
    assert parse_line("Feb 30 10:00:00 h sshd[1]: Failed password for a from 1.2.3.4 port 1 ssh2", 2025) is None


if __name__ == "__main__":
    test_failed_login()
    test_invalid_user()
    test_accepted_login_single_digit_day()
    test_unsupported_and_bad_lines()
    print("All log parser tests passed.")