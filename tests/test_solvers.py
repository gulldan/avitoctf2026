"""Offline regression checks for shared signing and PAM payload construction."""

import datetime
import io
import os
import unittest
import urllib.error
from email.message import Message
from unittest.mock import patch

from medhunter_signature import s3
from pamgate import solve_pamgate


class SolverTests(unittest.TestCase):
    def test_s3_requests_match_original_signatures(self):
        fixtures = [
            (
                "GET",
                "folder/a b.txt",
                b"",
                "84bb6f8f138ed3e68d76ef3d3ae19eb52f9815f5eb95c0b9b21e9c696f42cc8a",
                "folder/a%20b.txt",
            ),
            (
                "PUT",
                "incoming/job.json",
                b'{"key":"value"}',
                "ff60c246fb6d8c47bc8222fbc8f6bf3ad292c87d660e77edfc783f4e64247747",
                "incoming/job.json",
            ),
        ]
        credentials = {"STORAGE_ACCESS_KEY": "test-access", "STORAGE_SECRET_KEY": "test-secret"}
        fixed_time = datetime.datetime(2026, 1, 2, 3, 4, 5, tzinfo=datetime.UTC)
        for method, key, body, signature, encoded_key in fixtures:
            with (
                self.subTest(method=method),
                patch.dict(os.environ, credentials, clear=True),
                patch.object(s3.datetime, "datetime") as clock,
                patch.object(s3.urllib.request, "urlopen") as urlopen,
            ):
                clock.now.return_value = fixed_time
                response = urlopen.return_value.__enter__.return_value
                response.status = 200
                response.read.return_value = b"OK"
                assert s3.req(method, "test-bucket", key, body=body, ctype="application/json") == (
                    200,
                    b"OK",
                )
                request = urlopen.call_args.args[0]
                assert request.full_url == f"https://{s3.HOST}/test-bucket/{encoded_key}"
                assert request.get_method() == method
                assert request.get_header("Authorization").endswith(signature)
                assert request.data == (body if method == "PUT" else None)
                if method == "PUT":
                    assert request.get_header("Content-type") == "application/json"

    def test_s3_returns_error_body(self):
        with (
            patch.object(s3, "credentials", return_value=("test-access", "test-secret")),
            patch.object(s3.urllib.request, "urlopen") as urlopen,
        ):
            urlopen.side_effect = urllib.error.HTTPError(
                "https://example.test", 403, "Forbidden", Message(), io.BytesIO(b"denied")
            )
            assert s3.req("GET", "test-bucket", "key") == (403, b"denied")

    def test_pam_password_layout_and_wire_bytes(self):
        with patch.object(solve_pamgate.time, "time", return_value=59):
            payload = solve_pamgate.password(-6940).encode("latin-1")
        assert len(payload) == 62
        assert payload[:6] == b"812658"
        assert payload[7:9] == b"\xe4\xe4"
        assert payload[46:62] == b"AAAAAAAAAAAAAAAA"
        for index in (0, 10, 13):
            assert solve_pamgate.password(index) is None


if __name__ == "__main__":
    unittest.main()
