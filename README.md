# OIDC_ExternalID_API

This is an API application built using C# and .NET for managing users in Azure AD via Microsoft Graph.

---

## Azure AD API Permissions Required

This API uses Microsoft Graph and requires certain permissions to be granted to your Azure AD app registration. The type of token (delegated/user or application/app-only) and the required permissions depend on the endpoint:

| Endpoint                                 | Permission Type      | Required Microsoft Graph Permissions                |
|------------------------------------------|---------------------|----------------------------------------------------|
| `/Token/getTestToken`                    | Delegated           | User.Read, openid, offline_access                  |
| `/Token/getAppToken`                     | Application         | (No user context)                                  |
| `/Graph/invite`                          | Application         | User.Invite.All                                    |
| `/Graph/getUserById`                     | Both                | User.Read.All                                      |
| `/Graph/getUserByEmail`                  | Both                | User.Read.All                                      |
| `/Graph/updateUserById`                  | Application         | User.ReadWrite.All                                 |
| `/Graph/updateUserAttributesById`        | Application         | User.ReadWrite.All                                 |
| `/Graph/deleteUserById`                  | Application         | User.ReadWrite.All                                 |
| `/Graph/deleteUserByEmail`               | Application         | User.ReadWrite.All                                 |
| `/Graph/changePasswordById`              | Application         | User.ReadWrite.All                                 |
| `/Graph/changePasswordByEmail`           | Application         | User.ReadWrite.All                                 |
| `/Graph/changeOwnPassword`               | Delegated           | User.ReadWrite, User.ReadWrite.All                 |
| `/WeatherForecast`                       | None                | (Demo endpoint, no auth required)                  |

**Notes:**
- **Delegated**: The endpoint requires a user token (the user must be signed in and consent to the permissions).
- **Application**: The endpoint requires an app-only token (client credentials flow, no user context).
- Some endpoints (like getUserById/getUserByEmail) can work with either permission type, but most write/delete operations require application permissions for security.
- For `/Graph/changeOwnPassword`, the user must be authenticated as themselves (delegated token).
- For `/Token/getAppToken`, the app must be granted the required application permissions in Azure AD.

---

## API Usage Guide

### Authentication & Token Endpoints

#### 1. POST `/Token/getTestToken`
**Purpose:** Get a user (delegated) JWT access token using email and password.

**Request Body:**
```json
{
  "email": "user@yourtenant.onmicrosoft.com",
  "password": "UserPassword123!"
}
```
**Response:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOi..."
}
```
**Use:** Use this token as a Bearer token in the `Authorization` header for endpoints that require user authentication (e.g., `/Graph/changeOwnPassword`).

---

#### 2. POST `/Token/getAppToken`
**Purpose:** Get an app-only (client credentials) JWT access token.

**Request Body:** _None_

**Response:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOi..."
}
```
**Use:** Use this token for app-only operations or Graph API endpoints that support application permissions.

---

### User & Graph Endpoints

> All `/Graph` endpoints require a valid Bearer token in the `Authorization` header. Use a user token for delegated/user actions, or an app token for app-only actions (where supported).

---

#### 3. POST `/Graph/invite`
**Purpose:** Invite a new user (guest) to your Azure AD tenant.

**Query Parameter:**
- `email` (string): Email address to invite.

**Example:**
```
POST /Graph/invite?email=someone@gmail.com
```
**Response:** Invitation result object or error.

---

#### 4. GET `/Graph/getUserById`
**Purpose:** Get user details by object ID or email.

**Query Parameter:**
- `idOrEmail` (string): User object ID or email.

**Example:**
```
GET /Graph/getUserById?idOrEmail=user@yourtenant.onmicrosoft.com
```
**Response:** User object or error.

---

#### 5. GET `/Graph/getUserByEmail`
**Purpose:** Get user details by email.

**Query Parameter:**
- `email` (string): User email.

**Example:**
```
GET /Graph/getUserByEmail?email=user@yourtenant.onmicrosoft.com
```
**Response:** User object or error.

---

#### 6. PATCH `/Graph/updateUserById`
**Purpose:** Update user attributes by object ID or email.

**Query Parameter:**
- `idOrEmail` (string): User object ID or email.

**Request Body:**
```json
{
  "jobTitle": "Manager",
  "department": "IT"
}
```
**Example:**
```
PATCH /Graph/updateUserById?idOrEmail=user@yourtenant.onmicrosoft.com
```
**Response:** Success message or error.

---

#### 7. PATCH `/Graph/updateUserAttributesById`
**Purpose:** Update limited user attributes (displayName, jobTitle, department).

**Query Parameter:**
- `idOrEmail` (string): User object ID or email.

**Request Body:**
```json
{
  "displayName": "John Doe",
  "jobTitle": "Manager",
  "department": "IT"
}
```
**Example:**
```
PATCH /Graph/updateUserAttributesById?idOrEmail=user@yourtenant.onmicrosoft.com
```
**Response:** Success message or error.

---

#### 8. DELETE `/Graph/deleteUserById`
**Purpose:** Delete a user by object ID or email.

**Query Parameter:**
- `idOrEmail` (string): User object ID or email.

**Example:**
```
DELETE /Graph/deleteUserById?idOrEmail=user@yourtenant.onmicrosoft.com
```
**Response:** Success message or error.

---

#### 9. DELETE `/Graph/deleteUserByEmail`
**Purpose:** Delete a user by email.

**Query Parameter:**
- `email` (string): User email.

**Example:**
```
DELETE /Graph/deleteUserByEmail?email=user@yourtenant.onmicrosoft.com
```
**Response:** Success message or error.

---

#### 10. PATCH `/Graph/changePasswordById`
**Purpose:** (Admin) Change a user's password by object ID or email.

**Query Parameter:**
- `idOrEmail` (string): User object ID or email.

**Request Body:**
```json
{
  "newPassword": "NewPassword123!",
  "forceChangePasswordNextSignIn": true,
  "forceChangePasswordNextSignInWithMfa": false
}
```
**Example:**
```
PATCH /Graph/changePasswordById?idOrEmail=user@yourtenant.onmicrosoft.com
```
**Response:** Success message or error.

---

#### 11. PATCH `/Graph/changePasswordByEmail`
**Purpose:** (Admin) Change a user's password by email.

**Query Parameter:**
- `email` (string): User email.

**Request Body:** _Same as above._

**Example:**
```
PATCH /Graph/changePasswordByEmail?email=user@yourtenant.onmicrosoft.com
```
**Response:** Success message or error.

---

#### 12. POST `/Graph/changeOwnPassword`
**Purpose:** User changes their own password (self-service).

**Authorization:** Requires a valid user JWT token (from `/Token/getTestToken`).

**Request Body:**
```json
{
  "currentPassword": "OldPassword123!",
  "newPassword": "NewPassword456!",
  "confirmNewPassword": "NewPassword456!"
}
```
**Example:**
```
POST /Graph/changeOwnPassword
```
**Response:** Success message or error.

---

### Weather Endpoint (Demo Only)

#### 13. GET `/WeatherForecast`
**Purpose:** Returns a sample weather forecast (for demo/testing).

**Example:**
```
GET /WeatherForecast
```
**Response:** Array of weather forecast objects.

---

## General Notes

- All `/Graph` endpoints require a valid Bearer token in the `Authorization` header.
- Use `/Token/getTestToken` for user tokens (delegated/user actions).
- Use `/Token/getAppToken` for app tokens (app-only actions).
- For password reset scenarios, users must change their password via the Microsoft portal before using it for API authentication.