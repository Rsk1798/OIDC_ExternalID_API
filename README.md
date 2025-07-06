# OIDC_ExternalID_API

This is an API application built using C# and .NET for managing users in Azure AD via Microsoft Graph.

---

## Azure AD API Permissions Required

This API uses Microsoft Graph and requires certain permissions to be granted to your Azure AD app registration. The type of token (delegated/user or application/app-only) and the required permissions depend on the endpoint:


| Endpoint                                 | Permission Type     | Required Microsoft Graph Permissions               |
|------------------------------------------|---------------------|----------------------------------------------------|
| `/Token/authorize`                       | Delegated           | Directory.AccessAsUser.All, User.Read              |
| `/Token/callback`                        | Delegated           | Directory.AccessAsUser.All, User.Read              |
| `/Token/refresh`                         | Delegated           | Directory.AccessAsUser.All, User.Read              |
| `/Token/adminconsent`                    | Application         | (Admin consent for app permissions)                |
| `/Token/adminconsent-callback`           | Application         | (Admin consent callback)                           |
| `/Token/getAppOnlyToken`                 | Application         | (App-only token generation)                        |
| `/Token/testAppOnlyAccess`               | Application         | User.Read.All (for testing)                        |
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
| `/Graph/changeOwnPassword`               | Delegated           | Directory.AccessAsUser.All                         |
| `/Graph/changeOwnPasswordDelegated`      | Delegated           | Directory.AccessAsUser.All                         |
| `/WeatherForecast`                       | None                | (Demo endpoint, no auth required)                  |


**Notes:**
- **Delegated**: The endpoint requires a user token (the user must be signed in and consent to the permissions).
- **Application**: The endpoint requires an app-only token (client credentials flow, no user context).
- Some endpoints (like getUserById/getUserByEmail) can work with either permission type, but most write/delete operations require application permissions for security.
- For `/Graph/changeOwnPassword` and `/Graph/changeOwnPasswordDelegated`, the user must be authenticated as themselves (delegated token) with `Directory.AccessAsUser.All` permission. **These endpoints work for all account types that support password changes, including native Azure AD, federated, and social accounts (Google, Facebook, etc.).**
- For `/Token/getAppToken`, the app must be granted the required application permissions in Azure AD.
- **New OAuth 2.0 Authorization Code Flow**: The `/Token/authorize`, `/Token/callback`, and `/Token/refresh` endpoints implement the secure OAuth 2.0 authorization code flow as recommended by Microsoft.

---

## Authentication Flows

This API supports multiple authentication flows to accommodate different use cases:

### 1. OAuth 2.0 Authorization Code Flow (Recommended for Production)

This is the secure, production-ready authentication flow as recommended by Microsoft:

**Step 1: Request Authorization**
```
GET /Token/authorize?redirectUri={your_redirect_uri}&state={optional_state}
```

**Step 2: User is redirected to Microsoft login**
- User authenticates with Microsoft
- User consents to required permissions
- Microsoft redirects back to your callback URL with an authorization code

**Step 3: Exchange Code for Token**
```
GET /Token/callback?code={authorization_code}&state={state}
```

**Step 4: Refresh Token (when needed)**
```
POST /Token/refresh
Content-Type: application/json

{
  "refreshToken": "your_refresh_token"
}
```

**Benefits:**
- ✅ Secure (no username/password in API calls)
- ✅ Supports all account types (native, federated, social)
- ✅ Full MFA support
- ✅ Refresh token support
- ✅ Production-ready

### 2. Resource Owner Password Credentials (ROPC) Flow (Legacy)

The `/Token/getTestToken` endpoint uses ROPC flow for backward compatibility:

```
POST /Token/getTestToken
Content-Type: application/json

{
  "email": "user@yourtenant.onmicrosoft.com",
  "password": "UserPassword123!"
}
```

**Limitations:**
- ⚠️ Less secure (requires username/password)
- ⚠️ Limited federated account support
- ⚠️ No refresh token support
- ⚠️ Not recommended for production

### 3. Client Credentials Flow (App-Only)

The `/Token/getAppToken` endpoint for app-only operations:

```
POST /Token/getAppToken
```

**Use Case:** Administrative operations that don't require user context.

### 4. OAuth 2.0 Client Credentials Flow (App-Only Access)

This is the secure, production-ready app-only authentication flow as recommended by Microsoft for background services and daemon applications:

**Step 1: Request Admin Consent**
```
GET /Token/adminconsent?redirectUri={your_redirect_uri}&state={optional_state}
```

**Step 2: Administrator grants consent**
- Administrator is redirected to Microsoft admin consent page
- Administrator reviews and approves application permissions
- Microsoft redirects back to your callback URL with consent result

**Step 3: Get App-Only Token**
```
POST /Token/getAppOnlyToken?scope=https://graph.microsoft.com/.default
```

**Step 4: Test App-Only Access**
```
GET /Token/testAppOnlyAccess?accessToken={your_access_token}
```

**Benefits:**
- ✅ Secure (no user interaction required)
- ✅ Works for background services and daemons
- ✅ Administrative privileges without user context
- ✅ Production-ready for server-to-server scenarios
- ✅ Supports all application permissions

**Use Cases:**
- Background services that run without user interaction
- Daemon applications that need elevated privileges
- Server-to-server API calls
- Administrative operations across the entire tenant

**Required Azure AD Configuration:**
- Application permissions configured in Azure AD
- Admin consent granted for required permissions
- Client secret or certificate configured

---

## Password Change Endpoints Comparison

> **Note:**
> According to [Microsoft documentation](https://learn.microsoft.com/en-us/graph/api/user-changepassword?view=graph-rest-1.0&tabs=http), the `/me/changePassword` endpoint requires a signed-in user and only supports delegated permissions with the `Directory.AccessAsUser.All` permission. Application permissions are not supported. This applies to both `/Graph/changeOwnPassword` and `/Graph/changeOwnPasswordDelegated` endpoints in this API.

This API provides multiple password change endpoints with different capabilities:

| Endpoint                            | Token Type         | Works for All Account Types? | Use Case                                      |
|-------------------------------------|--------------------|------------------------------|-----------------------------------------------|
| `/Graph/changePasswordById`         | App-only           | No (Native Azure AD only)    | Admin changing user passwords                 |
| `/Graph/changePasswordByEmail`      | App-only           | No (Native Azure AD only)    | Admin changing user passwords                 |
| `/Graph/changeOwnPassword`          | Delegated (user)   | Yes (if user supports it)    | User changing their own password (Graph SDK)  |
| `/Graph/changeOwnPasswordDelegated` | Delegated (user)   | Yes (if user supports it)    | User changing their own password (Direct HTTP)|


**Key Differences:**
- **App-only endpoints** (`changePasswordById`, `changePasswordByEmail`): Only work for native Azure AD users. Cannot change passwords for federated, social, or external accounts.
- **Delegated endpoints** (`changeOwnPassword`, `changeOwnPasswordDelegated`): Work for all account types that support password changes, including Google, Facebook, and other federated accounts.
- **`changeOwnPasswordDelegated`** mimics the behavior of MVC applications by making direct HTTP calls to Microsoft Graph, ensuring compatibility with all account types.

---

## Password Complexity Handling

### Azure AD/Entra ID Enforcement
- **Azure AD automatically enforces password complexity** when using Microsoft Graph endpoints.
- Password requirements are configured in your Azure AD tenant settings.
- If a password doesn't meet complexity requirements, the Graph API returns an error.

### API Pre-Validation (Optional)
For better user experience, you can add client-side password complexity validation before calling the API:

```csharp
private bool IsPasswordComplex(string password)
{
    var hasMinLength = password.Length >= 8;
    var hasUpperCase = password.Any(char.IsUpper);
    var hasLowerCase = password.Any(char.IsLower);
    var hasDigit = password.Any(char.IsDigit);
    var hasSpecialChar = password.Any(c => !char.IsLetterOrDigit(c));
    return hasMinLength && hasUpperCase && hasLowerCase && hasDigit && hasSpecialChar;
}
```

**Note:** This pre-validation is optional and for user experience only. Azure AD will always enforce its own password policy regardless of any client-side checks.

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

**Important:** The new `/Graph/changeOwnPasswordDelegated` endpoint works for all account types that support password changes, including federated and social accounts.

---

## API Endpoint Authorization Overview

This table shows which endpoints require a token (authorization) and which do not, as well as the required token type:


| Endpoint                            | Requires Token? | Token Type          |
|-------------------------------------|-----------------|---------------------|
| `/Token/authorize`                  | No              | N/A                 |
| `/Token/callback`                   | No              | N/A                 |
| `/Token/refresh`                    | No              | N/A                 |
| `/Token/adminconsent`               | No              | N/A                 |
| `/Token/adminconsent-callback`      | No              | N/A                 |
| `/Token/getAppOnlyToken`            | No              | N/A                 |
| `/Token/testAppOnlyAccess`          | No              | N/A                 |
| `/Token/getTestToken`               | No              | N/A                 |
| `/Token/getAppToken`                | No              | N/A                 |
| `/WeatherForecast`                  | No              | N/A                 |
| `/Graph/changeOwnPassword`          | Yes             | User (delegated)    |
| `/Graph/changeOwnPasswordDelegated` | Yes             | User (delegated)    |
| `/Graph/getUserById`                | Yes             | User or App         |
| `/Graph/getUserByEmail`             | Yes             | User or App         |
| `/Graph/updateUserById`             | Yes             | App-only            |
| `/Graph/updateUserAttributesById`   | Yes             | App-only            |
| `/Graph/deleteUserById`             | Yes             | App-only            |
| `/Graph/deleteUserByEmail`          | Yes             | App-only            |
| `/Graph/changePasswordById`         | Yes             | App-only            |
| `/Graph/changePasswordByEmail`      | Yes             | App-only            |
| `/Graph/invite`                     | Yes             | App-only            |


**Summary:**
- All `/Graph/*` endpoints require a token except `/WeatherForecast`.
- `/Token/authorize`, `/Token/callback`, `/Token/refresh`, `/Token/adminconsent`, `/Token/adminconsent-callback`, `/Token/getAppOnlyToken`, `/Token/testAppOnlyAccess`, `/Token/getTestToken` and `/Token/getAppToken` are used to obtain tokens and do not require authorization themselves.
- Use a **user token** (from `/Token/getTestToken` or OAuth 2.0 flow) for `/Graph/changeOwnPassword` and `/Graph/changeOwnPasswordDelegated`.
- Use an **app token** (from `/Token/getAppToken` or `/Token/getAppOnlyToken`) for all other `/Graph/*` endpoints unless otherwise noted.

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

#### 1. POST `/Token/authorize`
**Purpose:** Initiate OAuth 2.0 authorization code flow.

**Query Parameter:**
- `redirectUri` (string): Redirect URI after successful authentication.
- `state` (string): Optional state parameter for security.

**Example:**
```
GET /Token/authorize?redirectUri={your_redirect_uri}&state={optional_state}
```
**Response:** Redirects to Microsoft login page.

---

#### 2. GET `/Token/callback`
**Purpose:** Handle OAuth 2.0 authorization code flow callback.

**Query Parameter:**
- `code` (string): Authorization code received from Microsoft.
- `state` (string): Optional state parameter for security.

**Example:**
```
GET /Token/callback?code={authorization_code}&state={state}
```
**Response:** Access token and refresh token.

---

#### 3. POST `/Token/refresh`
**Purpose:** Refresh an access token using a refresh token.

**Request Body:**
```json
{
  "refreshToken": "your_refresh_token"
}
```
**Response:** New access token.

---

#### 4. POST `/Token/getTestToken` (Legacy - ROPC Flow)
**Purpose:** Get a user (delegated) JWT access token using email and password (Resource Owner Password Credentials flow).

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

**Note:** This endpoint uses ROPC flow which is less secure and not recommended for production. Use the OAuth 2.0 authorization code flow instead.

---

#### 5. POST `/Token/getAppToken`
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

#### 6. GET `/Token/adminconsent`
**Purpose:** Request admin consent for application permissions (OAuth 2.0 client credentials flow).

**Query Parameters:**
- `redirectUri` (string): Redirect URI after admin consent (optional).
- `state` (string): Optional state parameter for security.

**Example:**
```
GET /Token/adminconsent?redirectUri=https://localhost:7110/Token/adminconsent-callback&state=12345
```
**Response:** Redirects to Microsoft admin consent page.

---

#### 7. GET `/Token/adminconsent-callback`
**Purpose:** Handle admin consent callback from Microsoft.

**Query Parameters:**
- `admin_consent` (string): Whether admin consent was granted.
- `tenant` (string): Tenant ID that granted consent.
- `state` (string): State parameter for security.
- `error` (string): Error message if consent failed.

**Example:**
```
GET /Token/adminconsent-callback?admin_consent=True&tenant=38d49456-54d4-455d-a8d6-c383c71e0a6d&state=12345
```
**Response:** Success or error message.

---

#### 8. POST `/Token/getAppOnlyToken`
**Purpose:** Get app-only token using OAuth 2.0 client credentials flow.

**Query Parameters:**
- `scope` (string): Scope for the token (defaults to `https://graph.microsoft.com/.default`).

**Example:**
```
POST /Token/getAppOnlyToken?scope=https://graph.microsoft.com/.default
```
**Response:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOi...",
  "expires_in": 3599,
  "ext_expires_in": 3599,
  "token_type": "Bearer"
}
```

---

#### 9. GET `/Token/testAppOnlyAccess`
**Purpose:** Test app-only access by calling Microsoft Graph API.

**Query Parameters:**
- `accessToken` (string): App-only access token to test.

**Example:**
```
GET /Token/testAppOnlyAccess?accessToken=eyJ0eXAiOiJKV1QiLCJhbGciOi...
```
**Response:**
```json
{
  "success": true,
  "message": "App-only access test successful",
  "userCount": 25,
  "sampleUsers": [
    {
      "id": "8afc02cb-4d62-4dba-b536-9f6d73e9be26",
      "displayName": "Conf Room Adams",
      "userPrincipalName": "Adams@Contoso.com"
    }
  ]
}
```

---

### User & Graph Endpoints

> Most `/Graph` endpoints require a valid Bearer token in the `Authorization` header. Use a user token for delegated/user actions, or an app token for app-only actions (where supported).

---

#### 10. POST `/Graph/invite`
**Purpose:** Invite a new user (guest) to your Azure AD tenant.

**Query Parameter:**
- `email` (string): Email address to invite.

**Example:**
```
POST /Graph/invite?email=someone@gmail.com
```
**Response:** Invitation result object or error.

---

#### 11. GET `/Graph/getUserById`
**Purpose:** Get user details by object ID or email.

**Query Parameter:**
- `idOrEmail` (string): User object ID or email.

**Example:**
```
GET /Graph/getUserById?idOrEmail=user@yourtenant.onmicrosoft.com
```
**Response:** User object or error.

---

#### 12. GET `/Graph/getUserByEmail`
**Purpose:** Get user details by email.

**Query Parameter:**
- `email` (string): User email.

**Example:**
```
GET /Graph/getUserByEmail?email=user@yourtenant.onmicrosoft.com
```
**Response:** User object or error.

---

#### 13. PATCH `/Graph/updateUserById`
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

#### 14. PATCH `/Graph/updateUserAttributesById`
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

#### 15. DELETE `/Graph/deleteUserById`
**Purpose:** Delete a user by object ID or email.

**Query Parameter:**
- `idOrEmail` (string): User object ID or email.

**Example:**
```
DELETE /Graph/deleteUserById?idOrEmail=user@yourtenant.onmicrosoft.com
```
**Response:** Success message or error.

---

#### 16. DELETE `/Graph/deleteUserByEmail`
**Purpose:** Delete a user by email.

**Query Parameter:**
- `email` (string): User email.

**Example:**
```
DELETE /Graph/deleteUserByEmail?email=user@yourtenant.onmicrosoft.com
```
**Response:** Success message or error.

---

#### 17. PATCH `/Graph/changePasswordById`
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

#### 18. PATCH `/Graph/changePasswordByEmail`
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

#### 19. POST `/Graph/changeOwnPassword`
**Purpose:** User changes their own password (self-service, delegated flow).

**Authorization:** Requires a valid user JWT token (from `/Token/getTestToken`).

> **Note:** This endpoint requires the `Directory.AccessAsUser.All` delegated permission, as per [Microsoft documentation](https://learn.microsoft.com/en-us/graph/api/user-changepassword?view=graph-rest-1.0&tabs=http). Application permissions are not supported for this operation.

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

#### 20. POST `/Graph/changeOwnPasswordDelegated`
**Purpose:** User changes their own password (self-service, delegated flow) using direct HTTP calls to Microsoft Graph.

**Authorization:** Requires a valid user JWT token (from `/Token/getTestToken`).

> **Note:** This endpoint requires the `Directory.AccessAsUser.All` delegated permission, as per [Microsoft documentation](https://learn.microsoft.com/en-us/graph/api/user-changepassword?view=graph-rest-1.0&tabs=http). Application permissions are not supported for this operation.

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
POST /Graph/changeOwnPasswordDelegated
```
**Response:** Success message or error.

**Notes:**
- Requires a valid user token with `Directory.AccessAsUser.All` delegated permission
- User must provide their current password
- No admin role or app-only permissions required
- Uses direct HTTP calls to Microsoft Graph
- **Works for all account types that support password changes, including native Azure AD, federated, and social accounts (Google, Facebook, etc.)**
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

#### 21. GET `/WeatherForecast`
**Purpose:** Returns a sample weather forecast (for demo/testing).

**Example:**
```