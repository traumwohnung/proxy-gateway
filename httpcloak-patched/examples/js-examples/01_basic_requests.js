/**
 * Basic HTTP Requests with httpcloak
 *
 * This is the simplest example - perfect for beginners!
 *
 * What you'll learn:
 * - Making GET and POST requests
 * - Sending query parameters and headers
 * - Reading response data (status, body, JSON)
 * - Using different HTTP methods
 *
 * Requirements:
 *   npm install httpcloak
 *
 * Run:
 *   node 01_basic_requests.js
 */

const httpcloak = require("httpcloak");

async function main() {
  // ============================================================
  // Example 1: Simple GET Request
  // ============================================================
  // The most basic request - just fetch a URL

  console.log("=".repeat(60));
  console.log("Example 1: Simple GET Request");
  console.log("-".repeat(60));

  // httpcloak.get() fetches a URL and returns a Response object
  let response = await httpcloak.get("https://httpbin.org/get");

  // The response contains all the data from the server
  console.log(`Status Code: ${response.statusCode}`); // 200 = success
  console.log(`Protocol: ${response.protocol}`); // h2 = HTTP/2, h3 = HTTP/3
  console.log(`OK: ${response.ok}`); // true if status < 400

  // ============================================================
  // Example 2: GET with Query Parameters
  // ============================================================
  // Query params are the ?key=value&key2=value2 part of URLs

  console.log("\n" + "=".repeat(60));
  console.log("Example 2: GET with Query Parameters");
  console.log("-".repeat(60));

  // Instead of manually building URLs, use the params option
  response = await httpcloak.get("https://httpbin.org/get", {
    params: {
      search: "httpcloak",
      page: 1,
      limit: 10,
    },
  });

  console.log(`Status: ${response.statusCode}`);
  console.log(`Final URL: ${response.url}`); // Shows the full URL with params

  // ============================================================
  // Example 3: POST with JSON Body
  // ============================================================
  // POST requests send data to the server

  console.log("\n" + "=".repeat(60));
  console.log("Example 3: POST with JSON Body");
  console.log("-".repeat(60));

  // The json option automatically:
  // - Converts your object to JSON
  // - Sets Content-Type: application/json header
  response = await httpcloak.post("https://httpbin.org/post", {
    json: {
      name: "httpcloak",
      version: "1.5.0",
      features: ["fingerprinting", "http3", "async"],
    },
  });

  console.log(`Status: ${response.statusCode}`);

  // Parse the JSON response
  const data = response.json();
  console.log("Server received:", data.json);

  // ============================================================
  // Example 4: POST with Form Data
  // ============================================================
  // Form data is what browsers send when you submit a form

  console.log("\n" + "=".repeat(60));
  console.log("Example 4: POST with Form Data");
  console.log("-".repeat(60));

  // The data option sends form-encoded data (like <form> submissions)
  response = await httpcloak.post("https://httpbin.org/post", {
    data: {
      username: "john_doe",
      password: "secret123",
      remember_me: "true",
    },
  });

  console.log(`Status: ${response.statusCode}`);
  const formData = response.json();
  console.log("Form data received:", formData.form);

  // ============================================================
  // Example 5: Custom Headers
  // ============================================================
  // Headers let you send extra information with your request

  console.log("\n" + "=".repeat(60));
  console.log("Example 5: Custom Headers");
  console.log("-".repeat(60));

  response = await httpcloak.get("https://httpbin.org/headers", {
    headers: {
      "X-Custom-Header": "my-value",
      "X-Request-ID": "abc-123-xyz",
      "Accept-Language": "en-US,en;q=0.9",
    },
  });

  console.log(`Status: ${response.statusCode}`);
  const headersData = response.json();
  console.log(`Custom header received: ${headersData.headers["X-Custom-Header"]}`);
  console.log(`Request ID received: ${headersData.headers["X-Request-Id"]}`);

  // ============================================================
  // Example 6: Reading Response Data
  // ============================================================
  // Different ways to access the response body

  console.log("\n" + "=".repeat(60));
  console.log("Example 6: Reading Response Data");
  console.log("-".repeat(60));

  response = await httpcloak.get("https://httpbin.org/json");

  // Status information
  console.log(`Status Code: ${response.statusCode}`);
  console.log(`OK (status < 400): ${response.ok}`);

  // Headers (object access)
  console.log(`Content-Type: ${response.headers["content-type"]}`);

  // Body in different formats
  console.log(`Body as Buffer: ${response.content.length} bytes`);
  console.log(`Body as string: ${response.text.length} characters`);

  // Parse JSON response
  const jsonData = response.json();
  console.log(`JSON parsed successfully: ${typeof jsonData}`);

  // ============================================================
  // Example 7: Other HTTP Methods
  // ============================================================
  // httpcloak supports all standard HTTP methods

  console.log("\n" + "=".repeat(60));
  console.log("Example 7: Other HTTP Methods");
  console.log("-".repeat(60));

  // PUT - update a resource
  response = await httpcloak.put("https://httpbin.org/put", {
    json: { updated: true },
  });
  console.log(`PUT: ${response.statusCode}`);

  // PATCH - partial update
  response = await httpcloak.patch("https://httpbin.org/patch", {
    json: { field: "new_value" },
  });
  console.log(`PATCH: ${response.statusCode}`);

  // DELETE - remove a resource
  response = await httpcloak.delete("https://httpbin.org/delete");
  console.log(`DELETE: ${response.statusCode}`);

  // HEAD - get headers only (no body)
  response = await httpcloak.head("https://httpbin.org/get");
  console.log(`HEAD: ${response.statusCode} (body length: ${response.content.length})`);

  // OPTIONS - check what methods are allowed
  response = await httpcloak.options("https://httpbin.org/get");
  console.log(`OPTIONS: ${response.statusCode}`);

  // ============================================================
  // Example 8: Error Handling
  // ============================================================
  // How to handle HTTP errors gracefully

  console.log("\n" + "=".repeat(60));
  console.log("Example 8: Error Handling");
  console.log("-".repeat(60));

  // 404 Not Found
  response = await httpcloak.get("https://httpbin.org/status/404");
  console.log(`404 Status: ${response.statusCode}, OK: ${response.ok}`);

  // 500 Server Error
  response = await httpcloak.get("https://httpbin.org/status/500");
  console.log(`500 Status: ${response.statusCode}, OK: ${response.ok}`);

  // raiseForStatus() throws an error for 4xx/5xx responses
  try {
    response = await httpcloak.get("https://httpbin.org/status/404");
    response.raiseForStatus(); // Throws HTTPCloakError for 4xx/5xx
  } catch (error) {
    console.log(`Caught error: ${error.message}`);
  }

  console.log("\n" + "=".repeat(60));
  console.log("All basic examples completed!");
  console.log("=".repeat(60));
  console.log(`
Next steps:
- Run 02_configure_and_presets.js to learn about browser presets
- Run 03_sessions_and_cookies.js to learn about sessions
- Run 06_async_concurrent.js to learn about concurrent requests
- Run 07_esm_example.mjs to see ES Modules syntax
`);
}

// Run the main function
main().catch(console.error);
