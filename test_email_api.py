import requests
import json

def test_send_email():
    url = "http://localhost:5000/api/send-email"
    payload = {
        "recipient_email": "test@example.com",
        "name": "Chandan",
        "domain": "brokergully.com",
        "industry": "Real Estate",
        "console_errors": "5",
        "load_time": "3.5s",
        "signature": "Antigravity AI"
    }
    headers = {
        'Content-Type': 'application/json'
    }

    try:
        response = requests.post(url, headers=headers, data=json.dumps(payload))
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.json()}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    # Note: This requires the Flask app to be running and SMTP configured.
    # To test without real SMTP, you'd need to mock smtplib in the app or use a test server.
    print("Testing Email API endpoint...")
    test_send_email()
