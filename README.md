# OIDC_ExternalID_API

This API enables secure user management in Azure AD via Microsoft Graph, using modern OAuth2 authentication flows. It is built with C# and .NET.

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

  A1-->|"Login/Signup"|B1
  B1-->|"OAuth2/OIDC Auth Request"|C1
  B1-->|"OAuth2/OIDC Auth Request"|C2
  B1-->|"Local Auth Request"|C3
  C1-->|"Token/Claims"|B2
  C2-->|"Token/Claims"|B2
  C3-->|"Token/Claims"|B2
  B2-->|"Issue JWT/Session"|A1
  A1-->|"API Call (with Token)"|B3
  B3-->|"User/Password Mgmt"|B4
  B4-->|"Graph API Call"|D1
  D1-->|"User/Password Ops"|B4
  B4-->|"Response"|B3
  B3-->|"API Response"|A1

---

## Visual Workflow of this API

sequenceDiagram
  participant User as "User/Client"
  participant Swagger as "Swagger UI / API Client"
  participant Token as "TokenController"
  participant Graph as "GraphController"
  participant IdP as "Identity Provider (Azure AD/Google/Local)"
  participant MSGraph as "Microsoft Graph API"

  User->>Swagger: Open Swagger UI / App
  User->>Swagger: Click Authorize/Login
  Swagger->>IdP: Redirect to Identity Provider (OIDC/OAuth2)
  IdP-->>Swagger: Return Token/Claims
  Swagger->>Token: Send Token for API Auth
  Token-->>User: Issue JWT/Session
  User->>Graph: Call API Endpoint (with Token)
  Graph->>Token: Validate Token
  Graph->>MSGraph: (If needed) Call Microsoft Graph API
  MSGraph-->>Graph: Return Data/Result
  Graph-->>User: API Response

---

## API Endpoint Authorization Overview

This table shows which endpoints require a token (authorization) and which do not, as well as the required token type:


| Endpoint                         | Requires Token? | Token Type       | Required Roles                    |
|----------------------------------|-----------------|------------------|-----------------------------------|
| `/Token/refresh`                 | No              | N/A              | N/A                               |
| `/Graph/getUserById`             | Yes             | User (delegated) | Global Admin, User Admin, Helpdesk Admin, User (own profile) |
| `/Graph/getUserByEmail`          | Yes             | User (delegated) | Global Admin, User Admin, Helpdesk Admin, User (own profile) |
| `/Graph/updateUserById`          | Yes             | User (delegated) | Global Admin, User Admin, User (own profile) |
| `/Graph/updateUserAttributesById`| Yes             | User (delegated) | Global Admin, User Admin, User (own profile) |
| `/Graph/deleteUserById`          | Yes             | User (delegated) | Global Admin, User Admin, User (own profile) |
| `/Graph/deleteUserByEmail`       | Yes             | User (delegated) | Global Admin, User Admin, User (own profile) |
| `/Graph/changePassword`          | Yes             | User (delegated) | User (own password only)          |
| `/Graph/resetPasswordById`       | Yes             | User (delegated) | Global Admin, User Admin, Helpdesk Admin |
| `/Graph/resetPasswordByEmail`    | Yes             | User (delegated) | Global Admin, User Admin, Helpdesk Admin |
| `/Graph/requestPasswordReset`    | No              | N/A              | Anyone (self-service)             |
| `/Graph/completePasswordReset`   | No              | N/A              | Anyone (self-service)             |
| `/WeatherForecast`               | No              | N/A              | N/A                               |


**Summary:**
- All `/Graph/*` endpoints require a token except `/WeatherForecast`.
- `/Token/refresh` is used to refresh tokens and does not require authorization itself.
- Use a **user token** (delegated) for all Graph endpoints.
- The password reset endpoints (`/Graph/resetPasswordById` and `/Graph/resetPasswordByEmail`) allow admins to reset passwords for other users.

---

## Role-Based Access Control

This API implements role-based access control based on Azure AD roles and permissions. The following roles can access different endpoints:

### **Global Administrator**
- **Full access** to all endpoints
- Can manage all users, reset passwords, and perform administrative operations
- Can delete users and manage the entire tenant

### **User Administrator** 
- **User management access** to most endpoints
- Can create, update, delete, and reset passwords for users
- Cannot manage other administrators or global settings
- **Accessible endpoints:**
  - `/Graph/getUserById` - Read user profiles
  - `/Graph/getUserByEmail` - Read user profiles by email
  - `/Graph/updateUserById` - Update user attributes
  - `/Graph/updateUserAttributesById` - Update limited user attributes
  - `/Graph/deleteUserById` - Delete users
  - `/Graph/deleteUserByEmail` - Delete users by email
  - `/Graph/resetPasswordById` - Reset user passwords
  - `/Graph/resetPasswordByEmail` - Reset user passwords by email

### **Helpdesk Administrator**
- **Limited user management access**
- Can read user profiles and reset passwords
- Cannot delete users or update sensitive attributes
- **Accessible endpoints:**
  - `/Graph/getUserById` - Read user profiles
  - `/Graph/getUserByEmail` - Read user profiles by email
  - `/Graph/resetPasswordById` - Reset user passwords
  - `/Graph/resetPasswordByEmail` - Reset user passwords by email

### **Regular Users**
- **Self-service access only**
- Can only manage their own profile and password
- Cannot access other users' data
- **Accessible endpoints:**
  - `/Graph/getUserById` - Read own profile (when using own ID)
  - `/Graph/getUserByEmail` - Read own profile (when using own email)
  - `/Graph/updateUserById` - Update own profile (when using own ID)
  - `/Graph/updateUserAttributesById` - Update own limited attributes (when using own ID)
  - `/Graph/deleteUserById` - Delete own profile (when using own ID)
  - `/Graph/deleteUserByEmail` - Delete own profile (when using own email)
  - `/Graph/changePassword` - Change own password
  - `/Graph/requestPasswordReset` - Request password reset (self-service)
  - `/Graph/completePasswordReset` - Complete password reset (self-service)

### **No Role Required**
- **Public endpoints** that don't require authentication
- **Accessible endpoints:**
  - `/Token/refresh` - Refresh access tokens
  - `/Graph/requestPasswordReset` - Request password reset (self-service)
  - `/Graph/completePasswordReset` - Complete password reset (self-service)
  - `/WeatherForecast` - Demo endpoint

---

## Required Microsoft Graph API Permissions

| Endpoint                        | Permission Type | Required Microsoft Graph Permissions      | Required Azure AD Role           |
|---------------------------------|-----------------|------------------------------------------|----------------------------------|
| `/Token/refresh`                | Delegated       | Directory.AccessAsUser.All, User.Read    | None                             |
| `/Graph/getUserById`            | Delegated       | User.Read.All                            | Global Admin, User Admin, Helpdesk Admin, User (own profile) |
| `/Graph/getUserByEmail`         | Delegated       | User.Read.All                            | Global Admin, User Admin, Helpdesk Admin, User (own profile) |
| `/Graph/updateUserById`         | Delegated       | User.ReadWrite.All                       | Global Admin, User Admin, User (own profile) |
| `/Graph/updateUserAttributesById`| Delegated      | User.ReadWrite.All                       | Global Admin, User Admin, User (own profile) |
| `/Graph/deleteUserById`         | Delegated       | User.ReadWrite.All                       | Global Admin, User Admin, User (own profile) |
| `/Graph/deleteUserByEmail`      | Delegated       | User.ReadWrite.All                       | Global Admin, User Admin, User (own profile) |
| `/Graph/changePassword`         | Delegated       | Directory.AccessAsUser.All               | User (own password only)         |
| `/Graph/resetPasswordById`      | Delegated       | User.ReadWrite.All                       | Global Admin, User Admin, Helpdesk Admin |
| `/Graph/resetPasswordByEmail`   | Delegated       | User.ReadWrite.All                       | Global Admin, User Admin, Helpdesk Admin |
| `/Graph/requestPasswordReset`   | None            | (Demo endpoint, no auth required)        | None                             |
| `/Graph/completePasswordReset`  | None            | (Demo endpoint, no auth required)        | None                             |
| `/WeatherForecast`              | None            | (Demo endpoint, no auth required)        | None                             |

---

## Supported Account Types for Token Generation and Password Change

| Account Type                                 | Token Generation | Password Change |
|----------------------------------------------|:----------------:|:--------------:|
| Azure AD user                               |       ✅         |      ✅        |
| Azure AD B2B guest                          |       ✅         |      ✅        |
| Social login (federated via Azure AD B2C/B2B)|       ✅         |      ✅*       |
| Local-only account (not in Azure AD)         |       ❌         |      ❌        |
| Social login (not federated)                 |       ❌         |      ❌        |

*Password change for social logins is only possible if the social account is federated through Azure AD B2C/B2B and the user is managed by your Azure AD tenant. Otherwise, password changes must be performed with the external provider (e.g., Google, Facebook).

---

## Quick Start

1. Register your API in Azure AD and set up permissions as above.
2. Run the API locally.
3. Open Swagger UI at `https://localhost:demo/swagger`.
4. Click **Authorize** and log in with your Azure AD, B2B, or federated social account.
5. Use the `/graph/changePassword` endpoint to change your password.

---

## Troubleshooting

- **Domain not valid:** Make sure the user's domain is allowed in Azure AD External Identities settings.
- **User not found:** Ensure the user is registered and has accepted any invitations.
- **Permission errors:** Confirm the app registration has the right Microsoft Graph permissions and consent is granted.
- **Redirect URI issues:** The redirect URI in Azure AD must match exactly what is used in Swagger UI.

---

## API Usage Guide

This section provides detailed documentation for all available endpoints in the API.

### Authentication & Token Endpoints

#### POST `/Token/refresh`
**Purpose:** Refresh an access token using a refresh token.

**Request Body:**
```json
{
  "refreshToken": "your_refresh_token"
}
```

**Response:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOi...",
  "refresh_token": "new_refresh_token_here",
  "expires_in": 3599,
  "token_type": "Bearer",
  "scope": "Directory.AccessAsUser.All User.Read"
}
```

**Use:** Use this endpoint to get a new access token when the current one expires.

---

### User Management Endpoints

#### GET `/Graph/getUserById`
**Purpose:** Get user details by object ID or email.

**Query Parameter:**
- `idOrEmail` (string): User object ID or email address.

**Authorization:** Requires Bearer token in Authorization header.

**Example:**
```
GET /Graph/getUserById?idOrEmail=user@yourtenant.onmicrosoft.com
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOi...
```

**Response:**
```json
{
  "id": "8afc02cb-4d62-4dba-b536-9f6d73e9be26",
  "displayName": "John Doe",
  "userPrincipalName": "john.doe@yourtenant.onmicrosoft.com",
  "mail": "john.doe@yourtenant.onmicrosoft.com",
  "jobTitle": "Software Engineer",
  "department": "Engineering"
}
```

---

#### GET `/Graph/getUserByEmail`
**Purpose:** Get user details by email address.

**Query Parameter:**
- `email` (string): User email address.

**Authorization:** Requires Bearer token in Authorization header.

**Example:**
```
GET /Graph/getUserByEmail?email=user@yourtenant.onmicrosoft.com
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOi...
```

**Response:** Same as `/Graph/getUserById`

---

#### PATCH `/Graph/updateUserById`
**Purpose:** Update user attributes by object ID or email.

**Query Parameter:**
- `idOrEmail` (string): User object ID or email address.

**Request Body:** Any valid user attributes as key-value pairs.
```json
{
  "jobTitle": "Senior Software Engineer",
  "department": "Engineering",
  "officeLocation": "Building A, Floor 3"
}
```

**Authorization:** Requires Bearer token in Authorization header.

**Example:**
```
PATCH /Graph/updateUserById?idOrEmail=user@yourtenant.onmicrosoft.com
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOi...
Content-Type: application/json

{
  "jobTitle": "Senior Software Engineer",
  "department": "Engineering"
}
```

**Response:**
```json
{
  "message": "User Updated Successfully."
}
```

---

#### PATCH `/Graph/updateUserAttributesById`
**Purpose:** Update limited user attributes (displayName, jobTitle, department).

**Query Parameter:**
- `idOrEmail` (string): User object ID or email address.

**Request Body:**
```json
{
  "displayName": "John Smith",
  "jobTitle": "Manager",
  "department": "IT"
}
```

**Authorization:** Requires Bearer token in Authorization header.

**Example:**
```
PATCH /Graph/updateUserAttributesById?idOrEmail=user@yourtenant.onmicrosoft.com
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOi...
Content-Type: application/json

{
  "displayName": "John Smith",
  "jobTitle": "Manager",
  "department": "IT"
}
```

**Response:**
```json
{
  "message": "User Updated with Limited Attributes"
}
```

---

#### DELETE `/Graph/deleteUserById`
**Purpose:** Delete a user by object ID or email.

**Query Parameter:**
- `idOrEmail` (string): User object ID or email address.

**Authorization:** Requires Bearer token in Authorization header.

**Example:**
```
DELETE /Graph/deleteUserById?idOrEmail=user@yourtenant.onmicrosoft.com
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOi...
```

**Response:**
```json
{
  "message": "User deleted successfully."
}
```

---

#### DELETE `/Graph/deleteUserByEmail`
**Purpose:** Delete a user by email address.

**Query Parameter:**
- `email` (string): User email address.

**Authorization:** Requires Bearer token in Authorization header.

**Example:**
```
DELETE /Graph/deleteUserByEmail?email=user@yourtenant.onmicrosoft.com
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOi...
```

**Response:**
```json
{
  "message": "User with email 'user@yourtenant.onmicrosoft.com' deleted successfully."
}
```

---

### Password Management Endpoints

#### POST `/Graph/changePassword`
**Purpose:** User changes their own password (self-service).

**Request Body:**
```json
{
  "currentPassword": "OldPassword123!",
  "newPassword": "NewPassword456!"
}
```

**Authorization:** Requires Bearer token in Authorization header (user's own token).

**Example:**
```
POST /Graph/changePassword
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOi...
Content-Type: application/json

{
  "currentPassword": "OldPassword123!",
  "newPassword": "NewPassword456!"
}
```

**Response:** `204 No Content` on success.

**Notes:**
- User can only change their own password
- Requires `Directory.AccessAsUser.All` delegated permission
- Works for Azure AD users, B2B guests, and federated social accounts

---

#### PATCH `/Graph/resetPasswordById`
**Purpose:** Admin resets a user's password by object ID or email.

**Query Parameter:**
- `idOrEmail` (string): User object ID or email address.

**Request Body:**
```json
{
  "newPassword": "NewPassword123!",
  "forceChangePasswordNextSignIn": true,
  "forceChangePasswordNextSignInWithMfa": false
}
```

**Authorization:** Requires Bearer token in Authorization header (admin token).

**Example:**
```
PATCH /Graph/resetPasswordById?idOrEmail=user@yourtenant.onmicrosoft.com
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOi...
Content-Type: application/json

{
  "newPassword": "NewPassword123!",
  "forceChangePasswordNextSignIn": true,
  "forceChangePasswordNextSignInWithMfa": false
}
```

**Response:**
```json
{
  "message": "Password reset successfully for user user@yourtenant.onmicrosoft.com. User will be required to change password on next sign-in: true"
}
```

---

#### PATCH `/Graph/resetPasswordByEmail`
**Purpose:** Admin resets a user's password by email address.

**Query Parameter:**
- `email` (string): User email address.

**Request Body:** Same as `/Graph/resetPasswordById`

**Authorization:** Requires Bearer token in Authorization header (admin token).

**Example:**
```
PATCH /Graph/resetPasswordByEmail?email=user@yourtenant.onmicrosoft.com
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOi...
Content-Type: application/json

{
  "newPassword": "NewPassword123!",
  "forceChangePasswordNextSignIn": true,
  "forceChangePasswordNextSignInWithMfa": false
}
```

**Response:**
```json
{
  "message": "Password reset successfully for user with email 'user@yourtenant.onmicrosoft.com'. User will be required to change password on next sign-in: true"
}
```

---

#### POST `/Graph/requestPasswordReset`
**Purpose:** Request a self-service password reset (Step 1: Send verification code).

**Request Body:**
```json
{
  "email": "user@yourtenant.onmicrosoft.com"
}
```

**Authorization:** None required (public endpoint).

**Example:**
```
POST /Graph/requestPasswordReset
Content-Type: application/json

{
  "email": "user@yourtenant.onmicrosoft.com"
}
```

**Response:**
```json
{
  "message": "If the email address exists in our system, a verification code has been sent.",
  "verificationCode": "123456",
  "expiresIn": "15 minutes"
}
```

**Notes:**
- Sends a 6-digit verification code to the user's email
- Code expires in 15 minutes
- Works for any user (self-service)
- In production, remove the `verificationCode` from the response

---

#### POST `/Graph/completePasswordReset`
**Purpose:** Complete self-service password reset (Step 2: Verify code and set new password).

**Request Body:**
```json
{
  "email": "user@yourtenant.onmicrosoft.com",
  "newPassword": "NewPassword123!",
  "verificationCode": "123456",
  "forceChangePasswordNextSignIn": true,
  "forceChangePasswordNextSignInWithMfa": false
}
```

**Authorization:** None required (public endpoint).

**Example:**
```
POST /Graph/completePasswordReset
Content-Type: application/json

{
  "email": "user@yourtenant.onmicrosoft.com",
  "newPassword": "NewPassword123!",
  "verificationCode": "123456",
  "forceChangePasswordNextSignIn": true,
  "forceChangePasswordNextSignInWithMfa": false
}
```

**Response:**
```json
{
  "message": "Password reset successfully. You can now log in with your new password.",
  "forceChangePasswordNextSignIn": true
}
```

**Notes:**
- Requires the verification code sent in Step 1
- Works for any user (self-service)
- Automatically clears the verification code after successful reset

---

### Demo Endpoint

#### GET `/WeatherForecast`
**Purpose:** Demo endpoint for testing API connectivity.

**Authorization:** None required.

**Example:**
```
GET /WeatherForecast
```

**Response:**
```json
[
  {
    "date": "2024-01-15",
    "temperatureC": 14,
    "temperatureF": 57,
    "summary": "Mild"
  },
  {
    "date": "2024-01-16",
    "temperatureC": 16,
    "temperatureF": 60,
    "summary": "Warm"
  }
]
```

---

### Error Responses

All endpoints may return the following error responses:

#### 400 Bad Request
```json
{
  "error": {
    "code": "Request_BadRequest",
    "message": "Invalid request format or missing required parameters"
  }
}
```

#### 401 Unauthorized
```json
{
  "error": {
    "code": "Authentication_MissingOrMalformed",
    "message": "Authorization header is missing or invalid"
  }
}
```

#### 403 Forbidden
```json
{
  "error": {
    "code": "InsufficientPermissions",
    "message": "User does not have sufficient permissions for this operation"
  }
}
```

#### 404 Not Found
```json
{
  "error": {
    "code": "Request_ResourceNotFound",
    "message": "User not found."
  }
}
```

#### 500 Internal Server Error
```json
{
  "error": {
    "code": "InternalServerError",
    "message": "An unexpected error occurred"
  }
}
```

---

### Testing with Swagger UI

1. **Open Swagger UI:** Navigate to `https://localhost:demo/swagger`
2. **Authorize:** Click the "Authorize" button and log in with your Azure AD account
3. **Test Endpoints:** Use the interactive interface to test all endpoints
4. **View Documentation:** Each endpoint includes detailed parameter descriptions

---

### Testing with cURL

#### Example: Get User by Email
```bash
curl -X GET "https://localhost:demo/Graph/getUserByEmail?email=user@yourtenant.onmicrosoft.com" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json"
```

#### Example: Update User Attributes
```bash
curl -X PATCH "https://localhost:demo/Graph/updateUserAttributesById?idOrEmail=user@yourtenant.onmicrosoft.com" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "displayName": "John Smith",
    "jobTitle": "Manager",
    "department": "IT"
  }'
```

#### Example: Change Password
```bash
curl -X POST "https://localhost:demo/Graph/changePassword" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "currentPassword": "OldPassword123!",
    "newPassword": "NewPassword456!"
  }'
```

---

## Authentication & Authorization (Azure AD)

### Supported Flow: OAuth2 Authorization Code with PKCE

- **Swagger UI** is configured for the Authorization Code flow with PKCE, supporting secure, interactive login for any Microsoft account (work, school, or personal).
- **Redirect URI:**
  - `https://localhost:demo/swagger/oauth2-redirect.html` (must be registered in Azure AD)
- **Supported account types:**
  - "Accounts in any organizational directory and personal Microsoft accounts (e.g. Skype, Xbox)"
- **Scope:**
  - `api.read` (Read access to API, as mentioned in Microsoft document)

#### How to Use in Swagger UI
1. Click **Authorize** in Swagger UI.
2. Log in with any Microsoft account (work, school, or personal).
3. Consent to the requested permissions.
4. The access token will be used for authorized API calls (e.g., password change endpoint).

> **Note:**
> - The access token must include the `Directory.AccessAsUser.All` delegated permission to use the password change endpoint. This is automatically requested by Swagger UI during login.
> - Some Microsoft Graph permissions may not be available to personal accounts. See [Microsoft Graph permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference).
> - The redirect URI must match exactly in Azure AD and Swagger config.

---

For further details or advanced scenarios, refer to Microsoft documentation on [OAuth2 flows in Azure AD](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow) and [Microsoft Graph permissions](https://learn.microsoft.com/en-us/graph/permissions-reference).