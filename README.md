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

### **No Role Required**
- **Public endpoints** that don't require authentication
- **Accessible endpoints:**
  - `/Token/refresh` - Refresh access tokens
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