import requests
import json
import csv
import concurrent.futures
import argparse
import sys
import time
import logging
import hashlib
from urllib.parse import urlparse, parse_qs


logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

class AuthzTester:
    def __init__(self, base_url, token1, token2, output_file=None):
        self.base_url = base_url
        self.token1 = token1 # User 1's auth token
        self.token2 = token2 # User 2's auth token
        self.output_file = output_file or "authz_test.csv"
        self.vulnerable_endpoints = []

        # Common API endpoints to test
        self.endpoints = self._load_endpoints()
        
        # User idenitifers
        self.user1_id = self._get_user_id(token1)
        self.user2_id = self._get_user_id(token2)

    def _load_endpoints(self):
        """Load API endpoints to test from configuration"""
        # In a real scenario, this would be loaded from a more comprehensive source
        return [
            {"path": "/api/v1/users/{user_id}/profile", "methods": ["GET", "PATCH"]},
            {"path": "/api/v1/users/{user_id}/posts", "methods": ["GET", "POST", "DELETE"]},
            {"path": "/api/v1/users/{user_id}/following", "methods": ["GET"]},
            {"path": "/api/v1/users/{user_id}/followers", "methods": ["GET"]},
            {"path": "/api/v1/users/{user_id}/saved", "methods": ["GET"]},
            {"path": "/api/v1/users/{user_id}/collections", "methods": ["GET", "POST"]},
            {"path": "/api/v1/direct/threads/{thread_id}", "methods": ["GET"]},
            {"path": "/api/v1/media/{media_id}/comments", "methods": ["GET", "POST", "DELETE"]},
            {"path": "/api/v1/accounts/edit", "methods": ["POST"]},
            {"path": "/api/v1/feed/user/{user_id}", "methods": ["GET"]},
            {"path": "/api/v1/friendships/{user_id}", "methods": ["GET", "POST"]},
            {"path": "/api/v1/direct/threads/{thread_id}/hide", "methods": ["POST"]},
            {"path": "/api/v1/stories/{user_id}/", "methods": ["GET"]},
            {"path": "/api/v1/highlights/{user_id}/", "methods": ["GET"]}
        ]
        
    def _get_user_id(self, token):
        """Get user ID from auth token"""
        headers = {"Authorization": f"Bearer {token}"}
        url = f"{self.base_url}/api/v1/accounts/current_user"
        try:
            response = requests.get(url, headers=headers, timeout=5)
            response.raise_for_status() # Raise HTTPError for 4xx and 5xx responses
            
            user_data = response.json()
            user_id = user_data.get("user", {}).get("pk")
            
            if user_id is None:
                logger.warning(f"User ID not found in response: {user_data}")
                
            return user_id
        
        except requests.exceptions.Timeout:
            logger.error("Request timed out while getting user ID")
        except requests.exceptions.RequestException as e:
            logger.error(f"HTTP Request error: {e}")
        except ValueError:
            logger.error("Invalid JSON response from server")
        except Exception as e:
            logger.exception(f"Unexpected error occurred: {e}")
            
        return None 
    
    def test_endpoints(self):
        """Test all endpoints for broken access control"""
        results = []
        total = len(self.endpoints) * 2 #  For both horizontal and vertical testing
        completed = 0
        
        print(f"Starting access control tests on {total} endpoint configurations...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            # Test horizontal privilege escalation (user1 accessing user2's resources)
            horizontal_futures = {
                executor.submit(
                    self.test_horizontal_access,
                    endpoint["path"],
                    method
                ): (endpoint["path"], method)
                for endpoint in self.endpoints
                for method in endpoint["methods"]
            }
            
            # Test vertical privilege escalation (accessing admin functions)
            vertical_futures = {
                executor.submit(
                    self.test_vertical_access,
                    endpoint["path"],
                    method
                ): (endpoint["path"], method)
                for endpoint in self.endpoints 
                for method in endpoint["methods"]
            }
            
            all_futures = {**horizontal_futures, **vertical_futures}
            
            for future in concurrent.futures.as_completed(all_futures):
                path, method = all_futures[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        if result["vulnerable"]:
                            self.vulnerable_endpoints.append(result)
                except Exception as e:
                    logger.error(f"Error testing {method} {path}: {e}")
                    
                completed += 1
                sys.stdout.write(f"\rProgress {completed}/{total} endpoints tested")
                sys.stdout.flush()
                
            print(f"\nTesting Complete!")
            self._save_results(results)
            return results
    
    def test_horizontal_access(self, path_template, method):
        """Test if user1 can access user2's resources"""
        # Replace user_id in path with user2's ID
        path = path_template.replace("{user_id}", str(self.user2_id))
        
        # For thread_id and media_id, we'd need to get valid IDs
        # In a real implementation, we would have a way to retrieve these
        if "{thread_id}" in path:
            path = path.replace("{thread_id}", "{dummy_thread_id}")
            return None
        if "{media_id}" in path:
            path = path.replace("{media_id}", "{dummy_media_id}")
            return path
        
        url = f"{self.base_url}{path}"
        headers = {"Authorization": f"Bearer {self.token1}"}
        

        try:
            if method == "GET":
                response = requests.get(url, headers, timeout=5)
            elif method == "POST":
                response = requests.post(url, headers, json={}, timeout=5)
            elif method == "PATCH":
                response = requests.patch(url, headers, json={}, timeout=5)
            elif method == "DELETE":
                response = requests.delete(url, headers, timeout=5)
            else:
                return None
            
            # Analyze response to determine if access control is broken
            vulnerable = self._is_horizontal_vulnerable(response)
            
            return {
                "endpoint": path_template,
                "method": method,
                "test_type": "horizontal",
                "status_code": response.status_code,
                "response_size": len(response.content),
                "vulnerable": vulnerable,
                "notes": "User1 can access User2's resources" if vulnerable else "Access properly restricted"
            }
