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
- For `/Graph/changeOwnPassword`, the user must be authenticated as themselves (delegated token). **Password change is only supported for Azure AD native users. Guest, social, or external users (e.g., Google, Facebook, B2C) will receive a structured error message and must change their password with their original provider or via the B2C/external identities password reset flow.**
- For `/Token/getAppToken`, the app must be granted the required application permissions in Azure AD.

---

## Password Reset Flow for Guest, Social, or External Users

If a guest, social, or external user (e.g., Gmail, Facebook, B2C) attempts to use the `/Graph/changeOwnPassword` endpoint, the API will return a structured error response:

**Example error response:**
```json
{
  "code": "PasswordChangeNotSupported",
  "message": "Password change is not supported for guest, social, or external users. Please change your password with your original provider (e.g., Google, Facebook) or use the external identities password reset flow if applicable.",
  "resetUrl": "https://<your-tenant>.b2clogin.com/<your-tenant>.onmicrosoft.com/oauth2/v2.0/authorize?p=B2C_1_passwordreset&client_id=<client-id>&nonce=defaultNonce&redirect_uri=<redirect-uri>&scope=openid&response_type=id_token&prompt=login"
}
```
- For social/guest users: They should use their provider's password reset (e.g., Google's "Forgot password?").
- For B2C local users: They should use the B2C password reset flow (the `resetUrl` above).

---

## API Endpoint Authorization Overview

This table shows which endpoints require a token (authorization) and which do not, as well as the required token type:

| Endpoint                        | Requires Token? | Token Type         |
|----------------------------------|----------------|--------------------|
| `/Token/getTestToken`            | No             | N/A                |
| `/Token/getAppToken`             | No             | N/A                |
| `/WeatherForecast`               | No             | N/A                |
| `/Graph/changeOwnPassword`       | Yes            | User (delegated)   |
| `/Graph/getUserById`             | Yes            | User or App        |
| `/Graph/getUserByEmail`          | Yes            | User or App        |
| `/Graph/updateUserById`          | Yes            | App-only           |
| `/Graph/updateUserAttributesById`| Yes            | App-only           |
| `/Graph/deleteUserById`          | Yes            | App-only           |
| `/Graph/deleteUserByEmail`       | Yes            | App-only           |
| `/Graph/changePasswordById`      | Yes            | App-only           |
| `/Graph/changePasswordByEmail`   | Yes            | App-only           |
| `/Graph/invite`                  | Yes            | App-only           |

**Summary:**
- All `/Graph/*` endpoints require a token except `/WeatherForecast`.
- `/Token/getTestToken` and `/Token/getAppToken` are used to obtain tokens and do not require authorization themselves.
- Use a **user token** (from `/Token/getTestToken`) for `/Graph/changeOwnPassword`.
- Use an **app token** (from `/Token/getAppToken`) for all other `/Graph/*` endpoints unless otherwise noted.

---

## Important Note on Password Reset Flow

**If a user's password is reset by an admin in the Azure Portal, the new (temporary) password CANNOT be used directly with the API.**

- The user must first log in to a Microsoft web portal (such as [https://myaccount.microsoft.com](https://myaccount.microsoft.com)) with the temporary password.
- The portal will prompt the user to set a new password.
- Only after this process is complete can the user use their new password with the API endpoints (such as `/Token/getTestToken` or `/Graph/changeOwnPassword`).
- This is a security feature enforced by Microsoft and cannot be bypassed by any API.

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
**Use:** Use this token as a Bearer token in the `Authorization` header for endpoints that require user authentication.

**Note:** If the user's password was recently reset by an admin, they must first log in to a Microsoft portal and change their password before using this endpoint.

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

> Most `/Graph` endpoints require a valid Bearer token in the `Authorization` header. Use a user token for delegated/user actions, or an app token for app-only actions (where supported).

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
**Purpose:** User changes their own password (self-service, delegated flow).

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

**Notes:**
- Requires a valid user token (delegated permissions)
- User must provide their current password
- No admin role or app-only permissions required
- Uses Microsoft Graph `/me/changePassword` endpoint
- **Password change is only supported for Azure AD native users. Guest, social, or external users (e.g., Google, Facebook, B2C) will receive a structured error message and must change their password with their original provider or via the B2C/external identities password reset flow.**
- **If the user's password was recently reset by an admin, they must first log in to a Microsoft portal and change their password before using this endpoint.**
- **Example error response for guest/social/external users:**
  ```json
  {
    "code": "PasswordChangeNotSupported",
    "message": "Password change is not supported for guest, social, or external users. Please change your password with your original provider (e.g., Google, Facebook) or use the external identities password reset flow if applicable.",
    "resetUrl": "https://<your-tenant>.b2clogin.com/<your-tenant>.onmicrosoft.com/oauth2/v2.0/authorize?p=B2C_1_passwordreset&client_id=<client-id>&nonce=defaultNonce&redirect_uri=<redirect-uri>&scope=openid&response_type=id_token&prompt=login"
  }
  ```

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

- Most `/Graph` endpoints require a valid Bearer token in the `Authorization` header.
- Use `/Token/getTestToken` for user tokens (delegated/user actions).
- Use `/Token/getAppToken` for app tokens (app-only actions).
- The `/Graph/changeOwnPassword` endpoint is designed for secure self-service password changes using delegated permissions. **Password change is only supported for Azure AD native users. Guest, social, or external users (e.g., Google, Facebook, B2C) will receive a structured error message and must change their password with their original provider or via the B2C/external identities password reset flow.**
- For password reset scenarios, users must change their password via the Microsoft portal before using it for API authentication.

---

## Azure AD Setup Instructions

### Required Application Permissions
To use this API, your Azure AD app registration needs these **Application permissions**:

1. **User.Read.All** - To read user data
2. **User.ReadWrite.All** - To update user passwords and attributes
3. **User.Invite.All** - To invite guest users

### How to Configure Permissions
1. Go to [Azure Portal](https://portal.azure.com) → **Azure Active Directory** → **App registrations**
2. Find your app registration
3. Go to **API permissions**
4. Click **Add a permission** → **Microsoft Graph** → **Application permissions**
5. Add the required permissions listed above
6. Click **Grant admin consent for [Your Tenant]**

### Testing the API
After configuring permissions, test with:

```bash
# Get app token
curl -X POST "https://localhost:7110/Token/getAppToken"

# Change password (no auth required)
curl -X POST "https://localhost:7110/Graph/changeOwnPassword" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@yourtenant.onmicrosoft.com",
    "newPassword": "NewPassword123!"
  }'
```