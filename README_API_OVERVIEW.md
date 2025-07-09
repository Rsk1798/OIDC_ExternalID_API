# OIDC_ExternalID_API (Open Testing Mode)

This API enables user management in Azure AD via Microsoft Graph. **Authorization, PKCE, and OAuth2 security are currently disabled for open testing.**

---

## Architecture Diagram of API

flowchart TD
  subgraph "User/Client"
    A1["User (Browser/App)"]
  end
  subgraph "OIDC_ExternalID_API"
    B1["Swagger UI / API Client"]
    B2["TokenController"]
    B3["GraphController"]
    B4["User Management Logic"]
  end
  subgraph "Identity Providers"
    C1["Azure AD (Workforce)"]
    C2["Google, Facebook, etc. (CIAM)"]
    C3["Local Accounts DB"]
  end
  subgraph "Microsoft Graph API"
    D1["Graph API"]
  end

  A1-->|"Open Swagger UI / API Call"|B1
  B1-->|"API Call (no auth required)"|B3
  B3-->|"User/Password Mgmt"|B4
  B4-->|"Graph API Call"|D1
  D1-->|"User/Password Ops"|B4
  B4-->|"Response"|B3
  B3-->|"API Response"|A1

---

## API Endpoint Overview (Open Mode)

| Endpoint                        | Method | Auth Required | Description                                 |
|----------------------------------|--------|---------------|---------------------------------------------|
| `/Graph/getUserById`             | GET    | No            | Get user by object ID or email              |
| `/Graph/getUserByEmail`          | GET    | No            | Get user by email                           |
| `/Graph/updateUserById`          | PATCH  | No            | Update user attributes by ID/email          |
| `/Graph/updateUserByEmail`       | PATCH  | No            | Update user attributes by email             |
| `/Graph/updateUserAttributesById`| PATCH  | No            | Update limited user attributes by ID/email  |
| `/Graph/updateUserAttributesByEmail`| PATCH| No            | Update limited user attributes by email     |
| `/Graph/deleteUserById`          | DELETE | No            | Delete user by object ID or email           |
| `/Graph/deleteUserByEmail`       | DELETE | No            | Delete user by email                        |
| `/Graph/changePassword`          | POST   | No            | Change own password                         |
| `/Graph/resetPasswordById`       | PATCH  | No            | Reset user password by ID/email             |
| `/Graph/resetPasswordByEmail`    | PATCH  | No            | Reset user password by email                |
| `/Graph/requestPasswordReset`    | POST   | No            | Request password reset (self-service)       |
| `/Graph/completePasswordReset`   | POST   | No            | Complete password reset (self-service)      |
| `/WeatherForecast`               | GET    | No            | Sample endpoint                             |

---

## Required Microsoft Graph API Permissions and Endpoint Access

| Endpoint                                 | Required Graph Permission(s)         | Who Can Use (User Type)                | Token Usage (in secure mode)           |
|-------------------------------------------|--------------------------------------|----------------------------------------|----------------------------------------|
| `/Graph/getUserById`                     | `User.Read.All`                      | Admins, User Admins, Helpdesk, Self    | Bearer token (delegated/admin)         |
| `/Graph/getUserByEmail`                  | `User.Read.All`                      | Admins, User Admins, Helpdesk, Self    | Bearer token (delegated/admin)         |
| `/Graph/updateUserById`                  | `User.ReadWrite.All`                 | Admins, User Admins, Self (own profile)| Bearer token (delegated/admin)         |
| `/Graph/updateUserByEmail`               | `User.ReadWrite.All`                 | Admins, User Admins, Self (own profile)| Bearer token (delegated/admin)         |
| `/Graph/updateUserAttributesById`        | `User.ReadWrite.All`                 | Admins, User Admins, Self (own profile)| Bearer token (delegated/admin)         |
| `/Graph/updateUserAttributesByEmail`     | `User.ReadWrite.All`                 | Admins, User Admins, Self (own profile)| Bearer token (delegated/admin)         |
| `/Graph/deleteUserById`                  | `User.ReadWrite.All`                 | Admins, User Admins, Self (own profile)| Bearer token (delegated/admin)         |
| `/Graph/deleteUserByEmail`               | `User.ReadWrite.All`                 | Admins, User Admins, Self (own profile)| Bearer token (delegated/admin)         |
| `/Graph/changePassword`                  | `Directory.AccessAsUser.All`         | Any signed-in user (self-service)      | Bearer token (delegated)               |
| `/Graph/resetPasswordById`               | `User.ReadWrite.All`                 | Admins, User Admins                    | Bearer token (admin)                   |
| `/Graph/resetPasswordByEmail`            | `User.ReadWrite.All`                 | Admins, User Admins                    | Bearer token (admin)                   |
| `/Graph/requestPasswordReset`            | None (self-service, email only)      | Anyone (self-service)                  | None                                   |
| `/Graph/completePasswordReset`           | `User.ReadWrite.All`                 | Anyone with valid verification code     | None (self-service, but token if secured)|
| `/WeatherForecast`                       | None                                 | Anyone                                 | None                                   |

### Legend
- **Admin**: Global Admin, User Admin, Helpdesk Admin (with sufficient rights)
- **Self**: The user acting on their own profile
- **Bearer token**: The `Authorization: Bearer <token>` header, required in secure/production mode

### Token Usage
- **In open/testing mode:** No token is required for any endpoint.
- **In secure/production mode:**
  - All `/Graph/*` endpoints (except password reset request/complete) require a valid Azure AD access token with the appropriate Microsoft Graph delegated permissions.
  - The token must be included in the `Authorization` header as a Bearer token.
  - The token must have the required scopes (see table above).

#### Example Token Usage (for production)

```http
GET /Graph/getUserById?idOrEmail=user@yourtenant.onmicrosoft.com
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOi...
```

#### Notes
- **Self-service password reset** (`/Graph/requestPasswordReset` and `/Graph/completePasswordReset`) is designed to work without a token, but in production, you may want to require a token for `/completePasswordReset` for extra security.
- **Admin endpoints** (reset/delete other users) require admin-level permissions and tokens.
- **User endpoints** (update/delete own profile, change password) require the user’s own token with delegated permissions.

---

## API Usage Guide

This section provides detailed documentation for all available endpoints in the API. Each entry includes the endpoint's purpose, required parameters, example requests (using curl), expected responses, and notes on open/testing vs. secure/production usage.

### `/Graph/getUserById`
- **Purpose:** Retrieve user details by object ID or email.
- **Method:** GET
- **Parameters:**
  - `idOrEmail` (query): User object ID or email address.
- **Example (open mode):**
  ```bash
  curl -X GET "https://your-api.azurewebsites.net/Graph/getUserById?idOrEmail=user@yourtenant.onmicrosoft.com"
  ```
- **Example (secure mode):**
  ```bash
  curl -X GET "https://your-api.azurewebsites.net/Graph/getUserById?idOrEmail=user@yourtenant.onmicrosoft.com" \
    -H "Authorization: Bearer <ACCESS_TOKEN>"
  ```
- **Response:**
  ```json
  {
    "id": "...",
    "displayName": "...",
    ...
  }
  ```

### `/Graph/getUserByEmail`
- **Purpose:** Retrieve user details by email address.
- **Method:** GET
- **Parameters:**
  - `email` (query): User email address.
- **Example:**
  ```bash
  curl -X GET "https://your-api.azurewebsites.net/Graph/getUserByEmail?email=user@yourtenant.onmicrosoft.com"
  ```
- **Response:** Same as above.

### `/Graph/updateUserById`
- **Purpose:** Update user attributes by object ID or email.
- **Method:** PATCH
- **Parameters:**
  - `idOrEmail` (query): User object ID or email address.
  - Request body: JSON object with fields to update.
- **Example:**
  ```bash
  curl -X PATCH "https://your-api.azurewebsites.net/Graph/updateUserById?idOrEmail=user@yourtenant.onmicrosoft.com" \
    -H "Content-Type: application/json" \
    -d '{"displayName": "John Smith", "jobTitle": "Manager"}'
  ```
- **Response:**
  ```json
  "User Updated Successfully."
  ```

### `/Graph/updateUserByEmail`
- **Purpose:** Update user attributes by email address.
- **Method:** PATCH
- **Parameters:**
  - `email` (query): User email address.
  - Request body: JSON object with fields to update.
- **Example:**
  ```bash
  curl -X PATCH "https://your-api.azurewebsites.net/Graph/updateUserByEmail?email=user@yourtenant.onmicrosoft.com" \
    -H "Content-Type: application/json" \
    -d '{"displayName": "Jane Doe"}'
  ```
- **Response:**
  ```json
  "User with email 'user@yourtenant.onmicrosoft.com' updated successfully."
  ```

### `/Graph/updateUserAttributesById`
- **Purpose:** Update limited user attributes by object ID or email.
- **Method:** PATCH
- **Parameters:**
  - `idOrEmail` (query): User object ID or email address.
  - Request body: JSON object with allowed fields (e.g., `displayName`, `jobTitle`, `department`).
- **Example:**
  ```bash
  curl -X PATCH "https://your-api.azurewebsites.net/Graph/updateUserAttributesById?idOrEmail=user@yourtenant.onmicrosoft.com" \
    -H "Content-Type: application/json" \
    -d '{"displayName": "New Name"}'
  ```
- **Response:**
  ```json
  "User Updated with Limited Attributes"
  ```

### `/Graph/updateUserAttributesByEmail`
- **Purpose:** Update limited user attributes by email address.
- **Method:** PATCH
- **Parameters:**
  - `email` (query): User email address.
  - Request body: JSON object with allowed fields.
- **Example:**
  ```bash
  curl -X PATCH "https://your-api.azurewebsites.net/Graph/updateUserAttributesByEmail?email=user@yourtenant.onmicrosoft.com" \
    -H "Content-Type: application/json" \
    -d '{"department": "IT"}'
  ```
- **Response:**
  ```json
  "User with email 'user@yourtenant.onmicrosoft.com' updated with limited attributes."
  ```

### `/Graph/deleteUserById`
- **Purpose:** Delete a user by object ID or email.
- **Method:** DELETE
- **Parameters:**
  - `idOrEmail` (query): User object ID or email address.
- **Example:**
  ```bash
  curl -X DELETE "https://your-api.azurewebsites.net/Graph/deleteUserById?idOrEmail=user@yourtenant.onmicrosoft.com"
  ```
- **Response:**
  ```json
  "User deleted successfully."
  ```

### `/Graph/deleteUserByEmail`
- **Purpose:** Delete a user by email address.
- **Method:** DELETE
- **Parameters:**
  - `email` (query): User email address.
- **Example:**
  ```bash
  curl -X DELETE "https://your-api.azurewebsites.net/Graph/deleteUserByEmail?email=user@yourtenant.onmicrosoft.com"
  ```
- **Response:**
  ```json
  "User with email 'user@yourtenant.onmicrosoft.com' deleted successfully."
  ```

### `/Graph/changePassword`
- **Purpose:** Change the signed-in user's own password.
- **Method:** POST
- **Parameters:**
  - Request body: `{ "currentPassword": "OldPassword123!", "newPassword": "NewPassword456!" }`
- **Example:**
  ```bash
  curl -X POST "https://your-api.azurewebsites.net/Graph/changePassword" \
    -H "Content-Type: application/json" \
    -d '{"currentPassword": "OldPassword123!", "newPassword": "NewPassword456!"}'
  ```
- **Response:** `204 No Content` on success.

### `/Graph/resetPasswordById`
- **Purpose:** Admin resets a user's password by object ID or email.
- **Method:** PATCH
- **Parameters:**
  - `idOrEmail` (query): User object ID or email address.
  - Request body: `{ "newPassword": "NewPassword123!", "forceChangePasswordNextSignIn": true, "forceChangePasswordNextSignInWithMfa": false }`
- **Example:**
  ```bash
  curl -X PATCH "https://your-api.azurewebsites.net/Graph/resetPasswordById?idOrEmail=user@yourtenant.onmicrosoft.com" \
    -H "Content-Type: application/json" \
    -d '{"newPassword": "NewPassword123!", "forceChangePasswordNextSignIn": true, "forceChangePasswordNextSignInWithMfa": false}'
  ```
- **Response:**
  ```json
  "Password reset successfully for user user@yourtenant.onmicrosoft.com. User will be required to change password on next sign-in: true"
  ```

### `/Graph/resetPasswordByEmail`
- **Purpose:** Admin resets a user's password by email address.
- **Method:** PATCH
- **Parameters:**
  - `email` (query): User email address.
  - Request body: Same as above.
- **Example:**
  ```bash
  curl -X PATCH "https://your-api.azurewebsites.net/Graph/resetPasswordByEmail?email=user@yourtenant.onmicrosoft.com" \
    -H "Content-Type: application/json" \
    -d '{"newPassword": "NewPassword123!", "forceChangePasswordNextSignIn": true, "forceChangePasswordNextSignInWithMfa": false}'
  ```
- **Response:**
  ```json
  "Password reset successfully for user with email 'user@yourtenant.onmicrosoft.com'. User will be required to change password on next sign-in: true"
  ```

### `/Graph/requestPasswordReset`
- **Purpose:** Request a password reset (self-service, sends verification code to email).
- **Method:** POST
- **Parameters:**
  - Request body: `{ "email": "user@yourtenant.onmicrosoft.com" }`
- **Example:**
  ```bash
  curl -X POST "https://your-api.azurewebsites.net/Graph/requestPasswordReset" \
    -H "Content-Type: application/json" \
    -d '{"email": "user@yourtenant.onmicrosoft.com"}'
  ```
- **Response:**
  ```json
  {
    "message": "If the email address exists in our system, a verification code has been sent.",
    "verificationCode": "123456", // For testing only
    "expiresIn": "15 minutes"
  }
  ```

### `/Graph/completePasswordReset`
- **Purpose:** Complete a password reset using the verification code (self-service).
- **Method:** POST
- **Parameters:**
  - Request body: `{ "email": "user@yourtenant.onmicrosoft.com", "newPassword": "NewPassword123!", "verificationCode": "123456" }`
- **Example:**
  ```bash
  curl -X POST "https://your-api.azurewebsites.net/Graph/completePasswordReset" \
    -H "Content-Type: application/json" \
    -d '{"email": "user@yourtenant.onmicrosoft.com", "newPassword": "NewPassword123!", "verificationCode": "123456"}'
  ```
- **Response:**
  ```json
  {
    "message": "Password reset successfully. You can now log in with your new password.",
    "forceChangePasswordNextSignIn": true
  }
  ```

### `/WeatherForecast`
- **Purpose:** Sample/test endpoint.
- **Method:** GET
- **Example:**
  ```bash
  curl -X GET "https://your-api.azurewebsites.net/WeatherForecast"
  ```
- **Response:**
  ```json
  [
    {
      "date": "2024-05-01",
      "temperatureC": 20,
      "temperatureF": 68,
      "summary": "Warm"
    },
    ...
  ]
  ```

---

## Usage Instructions

1. **Open Swagger UI:**
   - Go to `/swagger` endpoint of your API (e.g., `https://your-api.azurewebsites.net/swagger`).
2. **No Authorization Required:**
   - All endpoints are open for testing. No login or token is needed.
3. **Try Out Endpoints:**
   - Click on any endpoint, click **Try it out**, fill in parameters, and click **Execute**.
4. **Direct API Calls:**
   - You can also use `curl`, Postman, or any HTTP client to call the endpoints directly—no headers or tokens required.

---

## Example cURL Usage

```bash
curl -X GET "https://your-api.azurewebsites.net/Graph/getUserByEmail?email=user@yourtenant.onmicrosoft.com"
curl -X PATCH "https://your-api.azurewebsites.net/Graph/updateUserById?idOrEmail=user@yourtenant.onmicrosoft.com" -d '{"displayName": "John Smith"}' -H "Content-Type: application/json"
curl -X POST "https://your-api.azurewebsites.net/Graph/changePassword" -d '{"currentPassword": "OldPassword123!", "newPassword": "NewPassword456!"}' -H "Content-Type: application/json"
```

---

## Security Notice

- **This API is currently running in open mode for testing.**
- **No authentication or authorization is enforced.**
- **Do not use this configuration in production!**
- To re-enable security, uncomment the relevant code in `Program.cs` and controllers.

---

## CORS Notice

- CORS configuration is currently commented out. Cross-origin browser requests may be blocked unless CORS is re-enabled.
- For local or server-to-server testing, this is not an issue.

---

## How to Re-enable Security

1. Uncomment `app.UseAuthorization()` in `Program.cs`.
2. Uncomment `[Authorize]` attributes in controllers.
3. Uncomment Swagger/OpenAPI OAuth2 security configuration.
4. Uncomment CORS configuration if needed for browser-based clients.

---

## For More Information
- See the main `README.md` for full documentation, architecture, and security details.
- For Microsoft Graph API permissions and usage, see [Microsoft Graph permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference). 