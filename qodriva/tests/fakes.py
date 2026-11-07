"""Fictional credentials used by the tests.

Values are assembled at runtime so that no complete secret-looking string exists
in this repository (which also keeps secret scanners quiet when they scan it).
None of them is a real credential; the AWS values are the examples published in
the AWS documentation.
"""

PASSWORD = "".join(["Zq8vLm", "2Xr9Tp", "Wk4N"])
AWS_ACCESS_KEY_ID = "AKIA" + "IOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "".join(["wJalrXUtnFEMI/K7MDENG/", "bPxRfiCYEXAMPLEKEY"])
GITHUB_TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
SLACK_TOKEN = "xoxb" + "-1234567890-" + "abcdefghijkl"
STRIPE_KEY = "sk_" + "live_" + "A1b2C3d4E5f6G7h8I9j0K1l2"
GOOGLE_API_KEY = "AIza" + "A1b2C3d4E5" * 3 + "F6g7H"
JWT = "eyJ" + "hbGciOiJIUzI1NiJ9" + ".eyJ" + "zdWIiOiJkZW1vIn0" + "." + "c2lnbmF0dXJlZGVtbw"
PRIVATE_KEY_HEADER = "-----BEGIN RSA " + "PRIVATE KEY-----"

ALL_SECRETS = [
    PASSWORD,
    AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY,
    GITHUB_TOKEN,
    SLACK_TOKEN,
    STRIPE_KEY,
    GOOGLE_API_KEY,
    JWT,
    PRIVATE_KEY_HEADER,
]

# (expected rule, a line of source code that should trigger it)
DETECTION_CASES = [
    ("secrets.private-key", PRIVATE_KEY_HEADER),
    ("secrets.aws-access-key-id", f'key = "{AWS_ACCESS_KEY_ID}"'),
    ("secrets.aws-secret-access-key", f'aws_secret_access_key = "{AWS_SECRET_ACCESS_KEY}"'),
    ("secrets.github-token", f"value = {GITHUB_TOKEN}"),
    ("secrets.slack-token", f"SLACK={SLACK_TOKEN}"),
    ("secrets.stripe-live-key", f"stripe = '{STRIPE_KEY}'"),
    ("secrets.google-api-key", f"maps = '{GOOGLE_API_KEY}'"),
    ("secrets.jwt", f"Authorization: Bearer {JWT}"),
    ("secrets.url-credentials", f"DATABASE_URL=postgres://app_user:{PASSWORD}@db.internal:5432/app"),
    ("secrets.hardcoded-credential", f'db_password = "{PASSWORD}"'),
]
