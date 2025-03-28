import redis
import json
import hashlib
import time
import os
from cryptography.fernet import Fernet
from functools import wraps 


# Initialize Redis connection
redis_client = redis.Redis(
    host=os.environ.get('REDIS_HOST', 'localhost'),
    port=int(os.environ.get('REDIS_PORT', 6379)),
    password=os.environ.get('REDIS_PASSWORD', ''),
    ssl=True
)

# Encryption key management
def get_encryption_key():
    """Get or generate encryption key from secure storage"""
    key = os.environ.get('CACHE_ENCRYPTION_KEY')
    if not key:
        # In prod, use a secure key management service
        # like AWS KMS or HashiCorp Vault instead of sgenerating here
        key = Fernet.generate_key()
        os.environ['CACHE_ENCRYPTION_KEY'] = key.decode()
    return key if isinstance(key, bytes) else key.encode()

# Init encryption
fernet = Fernet(get_encryption_key())

def secure_cache(ttl=300):
    """
    Decorator for caching API responses securely
    
    Args:
        ttl: Cache time-to-live in seconds (default 5 minutes)
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Create unique key based on function name and arguments
            cache_key = f"{func.__name__}:{hashlib.sha256(str(args).encode() + str(kwargs).encode()).hexdigest()}"
            
            # Try to get from cache
            cached_data = redis_client.get(cache_key)
            if cached_data:
                try:
                    # Decrypt the cached data
                    decrypted_data = fernet.decrypt(cached_data)
                    return json.loads(decrypted_data)
                except Exception as e:
                    print(f"Cache decryption error: {e}")
                    # Cache may be corrupted, continue to fresh data
                    
            # Get fresh data
            data = func(*args, **kwargs)
            
            # Cache the results (encrypted)
            if data:
                try:
                    # Serialize and encrypt the data 
                    encrypted_data = fernet.encrypt(json.dumps(data).encode())
                    # Store with proper TTL
                    redis_client.setex(cache_key, encrypted_data, ttl)
                    
                    # Add to cache registry for potential invalidation
                    redis_client.sadd("cache_registry", cache_key)
                except Exception as e:
                    print(f"Cache encryption error: {e}")
                    # Cache may be corrupted, continue to fresh data
                    
            return data
        return wrapper
    return decorator

# Security functions for cache management
def invalidate_all_caches():
    """Invalidate all caches - useful for security incidents"""
    keys = redis_client.smembers("cache_registry")
    if keys:
        redis_client.delete(*keys)
        redis_client.delete("cache_registry")
        
def invalidate_user_caches(user_id):
    """Invalidate all caches for specific user - for logouts/password change"""
    pattern = f"*:user:{user_id}:*"
    keys = redis_client.keys(pattern)
    if keys:
        redis_client.delete(*keys)
        # Remove from registry
        for key in keys:
            redis_client.srem("cache_registry", key)

# Example usage
@secure_cache(ttl=900)  # 15 minutes
def get_user_permissions(user_id):
    """Get user permissions from backend service"""
    # In a real app, this would call an API or database
    time.sleep(2)  # Simulate API call
    return {
        "user_id": user_id,
        "permissions": ["read", "write"],
        "last_updated": time.time()
    }

# Usage
if __name__ == "__main__":
    # First call will hit the backend
    start = time.time()
    result1 = get_user_permissions("user123")
    print(f"First call took {time.time() - start:.2f}s: {result1}")
    
    # Second call will use the cache
    start = time.time()
    result2 = get_user_permissions("user123")
    print(f"Second call took {time.time() - start:.2f}s: {result2}")
    
    # When a user changes permissions or logs out
    invalidate_user_caches("user123")
    
    # After invalidation, this will hit the backend again
    start = time.time()
    result3 = get_user_permissions("user123")
    print(f"Call after invalidation took {time.time() - start:.2f}s: {result3}")
            
            
