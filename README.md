# Clever Cloud OAuth1 Example

A minimal Node.js application demonstrating the [OAuth 1.0a flow](https://developers.clever-cloud.com/developers/api/howto/#oauth1) with the Clever Cloud API. Zero external dependencies.

## Prerequisites

- A [Clever Cloud account](https://console.clever-cloud.com/)
- [Clever Tools CLI](https://github.com/CleverCloud/clever-tools) installed
- An OAuth consumer (see [Create an OAuth consumer](https://developers.clever-cloud.com/developers/api/howto/#create-an-oauth-consumer))
- Node.js 24+ for local development

## Deploy on Clever Cloud

Install Clever Tools and log in:

```bash
# Alternative install methods:
# https://www.clever.cloud/developers/doc/cli/install/
npm i -g clever-tools
clever login
```

Clone this repository and create the application:

```bash
git clone https://github.com/CleverCloud/oauth1-example
cd oauth1-example

clever create --type node

# Must match the base URL configured in your OAuth consumer
# For production, use a custom domain instead of cleverapps.io
clever domain add <example-domain>.cleverapps.io
clever domain favourite set <example-domain>.cleverapps.io

clever env set OAUTH_CONSUMER_KEY "your_consumer_key"
clever env set OAUTH_CONSUMER_SECRET "your_consumer_secret"
clever env set APP_HOST "$(clever domain favourite)"

clever deploy
clever open
```

## Local development

Create a `.env` file with your OAuth consumer credentials (base URL set to `http://localhost:8080`):

```env
OAUTH_CONSUMER_KEY=your_consumer_key
OAUTH_CONSUMER_SECRET=your_consumer_secret
```

```bash
npm run dev
```

The app listens on `http://localhost:8080` by default. Set `PORT` to change it.

## How it works

1. User clicks "Login with Clever Cloud"
2. Server obtains a request token and redirects to the Clever Cloud authorization page
3. After approval, Clever Cloud redirects back with a verifier
4. Server exchanges the verifier for an access token
5. Tokens are stored in the browser's `localStorage`
6. Client calls `/api/self`, server proxies the request to `GET /v2/self` with OAuth1 signing

## Project structure

```
├── server.js        # HTTP server and routing
├── oauth.js         # OAuth1 HMAC-SHA512 signing and flow
└── public/
    ├── index.html   # Page structure
    ├── style.css    # Design system
    ├── app.js       # Client-side logic and rendering
    └── logo.svg     # Clever Cloud logo
```

See the [full OAuth1 documentation](https://developers.clever-cloud.com/developers/api/howto/#oauth1) for details on the protocol.
