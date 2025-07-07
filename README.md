# OIDC_ExternalID_API

This API enables secure user management in Azure AD via Microsoft Graph, using modern OAuth2 authentication flows. It is built with C# and .NET.

---

## Authentication & Authorization (Azure AD)

### Supported Flow: OAuth2 Authorization Code with PKCE

- **Swagger UI** is configured for the Authorization Code flow with PKCE, supporting secure, interactive login for any Microsoft account (work, school, or personal).
- **Redirect URI:**
  - `https://localhost:7110/swagger/oauth2-redirect.html` (must be registered in Azure AD)
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

## Key Endpoints

| Endpoint                  | Method | Description                                 | Auth Required |
|--------------------------|--------|---------------------------------------------|--------------|
| `/graph/changePassword`  | POST   | User changes their own password (delegated) | Yes          |
| `/WeatherForecast`       | GET    | Demo endpoint, no auth required             | No           |

- The password change endpoint requires a valid Microsoft access token with the `Directory.AccessAsUser.All` delegated permission.
- Use the **Authorize** button in Swagger UI to obtain a token.

---

## Azure AD App Registration Checklist

- Register your API in Azure AD.
- Set **Supported account types** to: Any Microsoft account (multitenant + personal).
- Add the redirect URI: `https://localhost:7110/swagger/oauth2-redirect.html` (type: Web).
- Assign required Microsoft Graph API permissions (e.g., `Directory.AccessAsUser.All`).
- Grant admin consent for application permissions if needed.

---

## Token Usage and Permissions

- **Delegated user tokens** are required for the `/graph/changePassword` endpoint.
- The access token must have the `Directory.AccessAsUser.All` permission.
- When you log in via Swagger UI, the correct scope is requested and the token is automatically used for API calls.
- Application (app-only) tokens and legacy flows are not supported for password change.

---

## Troubleshooting

- **AADSTS500208:** The domain is not a valid login domain for the account type.
  - Ensure you are using a supported Microsoft account.
  - Make sure your app registration is set to allow any Microsoft account.
  - Confirm the redirect URI is registered in Azure AD.
- **CORS/PKCE/Redirect URI Issues:**
  - Always use the Authorization Code flow with PKCE in Swagger UI for browser-based authentication.
  - The redirect URI in Azure AD must match exactly what is used in Swagger UI.

---

## Quick Start

1. Clone the repo and configure your Azure AD app registration as described above.
2. Run the API locally.
3. Open Swagger UI at `https://localhost:7110/swagger`.
4. Click **Authorize**, log in, and test the endpoints.

### Example: Change Password via Swagger UI

1. Click **Authorize** and log in with your Microsoft account.
2. Go to the `/graph/changePassword` endpoint and click **Try it out**.
3. Enter the request body:
   ```json
   {
     "currentPassword": "yourCurrentPassword",
     "newPassword": "yourNewPassword"
   }
   ```
4. Click **Execute**. You should receive a `204 No Content` response on success.

---

For further details or advanced scenarios, refer to Microsoft documentation on [OAuth2 flows in Azure AD](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow) and [Microsoft Graph permissions](https://learn.microsoft.com/en-us/graph/permissions-reference).

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
| `/Token/oauth2/client-credentials`       | Application         | (App-only token generation)                        |
| `/Token/oauth2/authorization-url`        | None                | (URL generation only)                              |
| `/Token/oauth2/authorization-code`       | None                | (Token exchange only)                              |
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
| `/Token/oauth2/client-credentials`  | No              | N/A                 |
| `/Token/oauth2/authorization-url`   | No              | N/A                 |
| `/Token/oauth2/authorization-code`  | No              | N/A                 |
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
GET /Token/adminconsent?redirectUri=https://localhost:demo/Token/adminconsent-callback&state=12345
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

---

## Testing OAuth 2.0 Endpoints

### Testing Client Credentials Flow (App-Only)

**Step 1: Test Client Credentials Flow (Minimal)**
```bash
curl -X POST "https://localhost:demo/Token/oauth2/client-credentials" \
  -H "Content-Type: application/json" \
  -d '{
    "tokenName": "GraphToken"
  }'
```

**Step 1: Test Client Credentials Flow (Full)**
```bash
curl -X POST "https://localhost:demo/Token/oauth2/client-credentials" \
  -H "Content-Type: application/json" \
  -d '{
    "clientId": "your-client-id",
    "clientSecret": "your-client-secret",
    "tenantId": "your-tenant-id",
    "scope": "https://graph.microsoft.com/.default",
    "clientAuthentication": "basic_auth",
    "tokenName": "GraphToken"
  }'
```

**Expected Response:**
```json
{
  "token_name": "GraphToken",
  "grant_type": "client_credentials",
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOi...",
  "expires_in": 3600,
  "ext_expires_in": 3600,
  "token_type": "Bearer",
  "scope": "https://graph.microsoft.com/.default",
  "tenant_id": "your-tenant-id",
  "client_id": "your-client-id",
  "client_authentication": "basic_auth"
}
```

### Testing Authorization Code Flow (User Delegated)

**Step 1: Generate Authorization URL (Minimal)**
```bash
curl -X POST "https://localhost:demo/Token/oauth2/authorization-url" \
  -H "Content-Type: application/json" \
  -d '{
    "state": "test-state-123"
  }'
```

**Step 1: Generate Authorization URL (Full)**
```bash
curl -X POST "https://localhost:demo/Token/oauth2/authorization-url" \
  -H "Content-Type: application/json" \
  -d '{
    "clientId": "your-client-id",
    "tenantId": "your-tenant-id",
    "redirectUri": "https://oauth.pstmn.io/v1/callback",
    "scope": "https://graph.microsoft.com/.default",
    "state": "test-state-123"
  }'
```

**Expected Response:**
```json
{
  "auth_url": "https://login.microsoftonline.com/your-tenant-id/oauth2/v2.0/authorize?...",
  "tenant_id": "your-tenant-id",
  "client_id": "your-client-id",
  "redirect_uri": "https://oauth.pstmn.io/v1/callback",
  "scope": "https://graph.microsoft.com/.default",
  "state": "test-state-123",
  "instructions": {
    "step1": "Open the auth_url in your browser",
    "step2": "Sign in with your Microsoft account",
    "step3": "Grant consent to the requested permissions",
    "step4": "Copy the authorization code from the redirect URL",
    "step5": "Use the authorization code with /Token/oauth2/authorization-code endpoint"
  }
}
```

**Step 2: Open the authorization URL in your browser**
- Copy the `auth_url` from the response
- Open it in your browser
- Sign in with your Microsoft account
- Grant consent to the requested permissions
- You'll be redirected to a URL like: `https://oauth.pstmn.io/v1/callback?code=M.R3_BAY.c0...&state=test-state-123`
- Copy the `code` parameter value

**Step 3: Exchange Authorization Code for Token (Minimal)**
```bash
curl -X POST "https://localhost:demo/Token/oauth2/authorization-code" \
  -H "Content-Type: application/json" \
  -d '{
    "authorizationCode": "M.R3_BAY.c0..."
  }'
```

**Step 3: Exchange Authorization Code for Token (Full)**
```bash
curl -X POST "https://localhost:demo/Token/oauth2/authorization-code" \
  -H "Content-Type: application/json" \
  -d '{
    "clientId": "your-client-id",
    "clientSecret": "your-client-secret",
    "tenantId": "your-tenant-id",
    "authorizationCode": "M.R3_BAY.c0...",
    "redirectUri": "https://oauth.pstmn.io/v1/callback",
    "scope": "https://graph.microsoft.com/.default",
    "tokenName": "GraphToken",
    "clientAuthentication": "basic_auth"
  }'
```

**Expected Response:**
```json
{
  "token_name": "GraphToken",
  "grant_type": "authorization_code",
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOi...",
  "refresh_token": "M.R3_BAY.c0...",
  "expires_in": 3600,
  "token_type": "Bearer",
  "scope": "https://graph.microsoft.com/.default",
  "tenant_id": "your-tenant-id",
  "client_id": "your-client-id",
  "redirect_uri": "https://oauth.pstmn.io/v1/callback",
  "client_authentication": "basic_auth"
}
```

### Testing in Swagger UI

1. **Open Swagger UI**: Navigate to `https://localhost:demo/swagger`
2. **Test Client Credentials Flow**:
   - Find the `POST /Token/oauth2/client-credentials` endpoint
   - Click "Try it out"
   - Enter your request body (you can leave clientId and clientSecret empty to use appsettings values)
   - Click "Execute"
3. **Test Authorization URL Generation**:
   - Find the `POST /Token/oauth2/authorization-url` endpoint
   - Click "Try it out"
   - Enter your request body
   - Click "Execute"
   - Copy the `auth_url` and open it in your browser
4. **Test Authorization Code Exchange**:
   - Find the `POST /Token/oauth2/authorization-code` endpoint
   - Click "Try it out"
   - Enter your request body with the authorization code from step 3
   - Click "Execute"

### Testing with Postman

You can also test these endpoints using Postman:

1. **Client Credentials Flow**:
   - Method: `POST`
   - URL: `https://localhost:demo/Token/oauth2/client-credentials`
   - Headers: `Content-Type: application/json`
   - Body (raw JSON):
     ```json
     {
       "clientId": "your-client-id",
       "clientSecret": "your-client-secret",
       "scope": "https://graph.microsoft.com/.default",
       "clientAuthentication": "basic_auth",
       "tokenName": "GraphToken"
     }
     ```

2. **Authorization Code Flow**:
   - Follow the same steps as above, but use the authorization URL and code exchange endpoints

### Simplified Usage with appsettings.json

The OAuth 2.0 endpoints are designed to work seamlessly with your `appsettings.json` configuration. You can use them in two ways:

#### **Minimal Usage (Recommended)**
Use the default values from your `appsettings.json`:

```json
{
  "tokenName": "GraphToken"
}
```

This will automatically use:
- `TenantId` from `AzureAd:TenantId`
- `ClientId` from `AzureAd:ClientId` 
- `ClientSecret` from `AzureAd:ClientSecret`
- `Scope` defaults to `https://graph.microsoft.com/.default`
- `ClientAuthentication` defaults to `basic_auth`
- `RedirectUri` defaults to `https://oauth.pstmn.io/v1/callback`

#### **Full Usage (Override Defaults)**
Provide specific values to override the defaults:

```json
{
  "clientId": "your-client-id",
  "clientSecret": "your-client-secret",
  "tenantId": "your-tenant-id",
  "scope": "https://graph.microsoft.com/.default",
  "clientAuthentication": "basic_auth",
  "tokenName": "GraphToken"
}
```

### Important Notes

- **Configuration Priority**: Request parameters override appsettings.json values
- **Client Authentication**: You can choose between "basic_auth" (sends credentials in Authorization header) or "body" (sends credentials in request body)
- **Scope**: The default scope is `https://graph.microsoft.com/.default` for app-only tokens
- **Redirect URI**: For authorization code flow, you can use any valid redirect URI, but it must match between the authorization URL and token exchange
- **State Parameter**: Always validate the state parameter in production to prevent CSRF attacks
- **Error Handling**: All endpoints return structured error responses with detailed messages
- **Token Security**: Never expose client secrets in client-side code or logs
- **Production Use**: These endpoints are designed for server-to-server communication and should not be exposed to end users directly
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