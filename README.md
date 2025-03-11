Matteo Steinbach

# Google OAuth Rust Implementation

A "secure" Rust implementation of Google OAuth 2.0 authentication using Warp web framework and JWT validation.

## Features

- OAuth 2.0 authentication flow with PKCE
- JWT validation with Google's public keys
- Session state management
- HTML templating with Askama
- Environment configuration
- Error handling with proper rejection

## Prerequisites

- Rust 1.65+
- Cargo
- Google Cloud Platform account
- Registered OAuth client credentials

## Setup

1. **Clone the repository**

   ```bash
   git clone https://github.com/yourusername/google-oauth-rs.git
   cd google-oauth-rs
   ```
2. **Install dependencies**

   ```bash
   cargo build
   ```
3. **Create `.env` file**

   ```env
   CLIENT_ID=your_google_client_id
   CLIENT_SECRET=your_google_client_secret
   ```
4. **Google Cloud Setup**

   - Create OAuth credentials at [Google Cloud Console](https://console.cloud.google.com/)
   - Add `http://localhost:8080/callback` to authorized redirect URIs
   - Enable "OpenID Connect" in the consent screen

## Running the Application

```bash
cargo run
```

Server will start at: `http://localhost:8080`

## File Structure

```
.
├── src/
│   ├── main.rs            # Application entry point and route configuration
│   ├── handlers.rs        # Request handlers and business logic
│   ├── jwks.rs            # JWKS fetching and key management
│   └── templates/         # Askama HTML templates
│       └── callback.html  # Post-auth user display template
├── static/                # Static files (CSS, images)
│   ├── logo.png           # Application logo
│   └── style.css          # CSS styles
├── target/                # Compiled output
├── .env                   # Environment configuration
└── Cargo.toml             # Dependency management           # Dependency management
```

# Key Files Explained

### 1. `src/main.rs`

- Configures Warp web server and routes
- Sets up shared application state
- Combines routes:
  - `/login` - Initiate OAuth flow
  - `/callback` - OAuth redirect handler
  - Static file serving
- Manages dependency injection

### 2. `src/handlers.rs`

Contains core authentication logic:

- `login_handler`:
  - Generates PKCE challenges
  - Creates authorization URL
  - Manages CSRF states
- `callback_handler`:
  - Validates state parameter
  - Exchanges authorization code for tokens
  - Validates JWT using JWKS
  - Renders user information

### 3. `src/jwks.rs`

- `fetch_jwks`: Retrieves JSON Web Key Set from Google
- Key caching and management
- JWT header validation

### 4. `templates/callback.html`

Askama template displaying:

- User's name
- User's email
- Authentication status

### 5. `static/`

- `logo.png`: Application logo
- `style.css`: CSS styles for the application

## Environment Variables

| Variable          | Description                | Example Value                                                    |
| ----------------- | -------------------------- | ---------------------------------------------------------------- |
| `CLIENT_ID`     | Google OAuth client ID     | 1234567890-abcdefghijklmnopqrstuvwxyz.apps.googleusercontent.com |
| `CLIENT_SECRET` | Google OAuth client secret | ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcd                                  |
| `JWKS_URI`      | Google's JWKS endpoint     | https://www.googleapis.com/oauth2/v3/certs                       |

## Authentication Flow

1. User visits `/login`
2. Application:
   - Generates PKCE verifier/challenge
   - Creates state token
   - Redirects to Google's authorization endpoint
3. User authenticates with Google
4. Google redirects to `/callback` with code and state
5. Application:
   - Validates state parameter
   - Exchanges code for tokens
   - Validates JWT signature
   - Verifies token claims
   - Displays user information

## Security Features

- PKCE (Proof Key for Code Exchange)
- CSRF protection with state parameter
- JWT signature verification
- Token expiration validation
- Audience validation
- Secure secret management
- HTTPS-only cookie handling

## Dependencies

| Crate            | Purpose                         |
| ---------------- | ------------------------------- |
| `warp`         | Web server framework            |
| `oauth2`       | OAuth client implementation     |
| `jsonwebtoken` | JWT validation                  |
| `askama`       | HTML templating                 |
| `dotenv`       | Environment variable management |
| `serde`        | Serialization/deserialization   |
| `reqwest`      | HTTP client for JWKS fetching   |

## Troubleshooting

Common Issues:

- **Missing .env file**: Copy `.env.example` to `.env`
- **Invalid credentials**: Verify Google OAuth client config
- **Port conflicts**: Ensure port 8080 is available
- **Certificate issues**: Use latest root certificates
- **Dependency issues**: Run `cargo update`

## License

MIT License - See [LICENSE](LICENSE) for details

**Note**: Implementation not properly tested for vulnerabilities only use at your own risk as in with edges but should be fine probably; It's also made by a mid rust programmer which is me so I hope its fine; I will put it public on my github once the deadline is past.
