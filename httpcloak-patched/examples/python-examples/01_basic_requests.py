#!/usr/bin/env python3
"""
Basic HTTP Requests with httpcloak

This is the simplest example - perfect for beginners!

What you'll learn:
- Making GET and POST requests
- Sending query parameters and headers
- Reading response data (status, body, JSON)
- Using different HTTP methods

Requirements:
    pip install httpcloak

Run:
    python 01_basic_requests.py
"""

import httpcloak

# ============================================================
# Example 1: Simple GET Request
# ============================================================
# The most basic request - just fetch a URL

print("=" * 60)
print("Example 1: Simple GET Request")
print("-" * 60)

# httpcloak.get() fetches a URL and returns a Response object
response = httpcloak.get("https://httpbin.org/get")

# The response contains all the data from the server
print(f"Status Code: {response.status_code}")  # 200 = success
print(f"Protocol: {response.protocol}")         # h2 = HTTP/2, h3 = HTTP/3
print(f"OK: {response.ok}")                     # True if status < 400

# ============================================================
# Example 2: GET with Query Parameters
# ============================================================
# Query params are the ?key=value&key2=value2 part of URLs

print("\n" + "=" * 60)
print("Example 2: GET with Query Parameters")
print("-" * 60)

# Instead of manually building URLs, use the params argument
response = httpcloak.get(
    "https://httpbin.org/get",
    params={
        "search": "httpcloak",
        "page": 1,
        "limit": 10
    }
)

print(f"Status: {response.status_code}")
print(f"Final URL: {response.url}")  # Shows the full URL with params

# ============================================================
# Example 3: POST with JSON Body
# ============================================================
# POST requests send data to the server

print("\n" + "=" * 60)
print("Example 3: POST with JSON Body")
print("-" * 60)

# The json= argument automatically:
# - Converts your dict to JSON
# - Sets Content-Type: application/json header
response = httpcloak.post(
    "https://httpbin.org/post",
    json={
        "name": "httpcloak",
        "version": "1.5.0",
        "features": ["fingerprinting", "http3", "async"]
    }
)

print(f"Status: {response.status_code}")

# Parse the JSON response
data = response.json()
print(f"Server received: {data.get('json')}")

# ============================================================
# Example 4: POST with Form Data
# ============================================================
# Form data is what browsers send when you submit a form

print("\n" + "=" * 60)
print("Example 4: POST with Form Data")
print("-" * 60)

# The data= argument sends form-encoded data
# (like <form> submissions)
response = httpcloak.post(
    "https://httpbin.org/post",
    data={
        "username": "john_doe",
        "password": "secret123",
        "remember_me": "true"
    }
)

print(f"Status: {response.status_code}")
data = response.json()
print(f"Form data received: {data.get('form')}")

# ============================================================
# Example 5: Custom Headers
# ============================================================
# Headers let you send extra information with your request

print("\n" + "=" * 60)
print("Example 5: Custom Headers")
print("-" * 60)

response = httpcloak.get(
    "https://httpbin.org/headers",
    headers={
        "X-Custom-Header": "my-value",
        "X-Request-ID": "abc-123-xyz",
        "Accept-Language": "en-US,en;q=0.9"
    }
)

print(f"Status: {response.status_code}")
data = response.json()
print(f"Custom header received: {data['headers'].get('X-Custom-Header')}")
print(f"Request ID received: {data['headers'].get('X-Request-Id')}")

# ============================================================
# Example 6: Reading Response Data
# ============================================================
# Different ways to access the response body

print("\n" + "=" * 60)
print("Example 6: Reading Response Data")
print("-" * 60)

response = httpcloak.get("https://httpbin.org/json")

# Status information
print(f"Status Code: {response.status_code}")
print(f"OK (status < 400): {response.ok}")

# Headers (dict-like access)
print(f"Content-Type: {response.headers.get('content-type')}")

# Body in different formats
print(f"Body as bytes: {len(response.content)} bytes")
print(f"Body as string: {len(response.text)} characters")

# Parse JSON response
json_data = response.json()
print(f"JSON parsed successfully: {type(json_data).__name__}")

# ============================================================
# Example 7: Other HTTP Methods
# ============================================================
# httpcloak supports all standard HTTP methods

print("\n" + "=" * 60)
print("Example 7: Other HTTP Methods")
print("-" * 60)

# PUT - update a resource
response = httpcloak.put(
    "https://httpbin.org/put",
    json={"updated": True}
)
print(f"PUT: {response.status_code}")

# PATCH - partial update
response = httpcloak.patch(
    "https://httpbin.org/patch",
    json={"field": "new_value"}
)
print(f"PATCH: {response.status_code}")

# DELETE - remove a resource
response = httpcloak.delete("https://httpbin.org/delete")
print(f"DELETE: {response.status_code}")

# HEAD - get headers only (no body)
response = httpcloak.head("https://httpbin.org/get")
print(f"HEAD: {response.status_code} (body length: {len(response.content)})")

# OPTIONS - check what methods are allowed
response = httpcloak.options("https://httpbin.org/get")
print(f"OPTIONS: {response.status_code}")

# ============================================================
# Example 8: Error Handling
# ============================================================
# How to handle HTTP errors gracefully

print("\n" + "=" * 60)
print("Example 8: Error Handling")
print("-" * 60)

# 404 Not Found
response = httpcloak.get("https://httpbin.org/status/404")
print(f"404 Status: {response.status_code}, OK: {response.ok}")

# 500 Server Error
response = httpcloak.get("https://httpbin.org/status/500")
print(f"500 Status: {response.status_code}, OK: {response.ok}")

# raise_for_status() throws an exception for error status codes
try:
    response = httpcloak.get("https://httpbin.org/status/404")
    response.raise_for_status()  # Raises HTTPCloakError for 4xx/5xx
except httpcloak.HTTPCloakError as e:
    print(f"Caught error: {e}")

print("\n" + "=" * 60)
print("All basic examples completed!")
print("=" * 60)
print("""
Next steps:
- Run 02_configure_and_presets.py to learn about browser presets
- Run 03_sessions_and_cookies.py to learn about sessions
- Run 05_async_requests.py to learn about concurrent requests
""")
