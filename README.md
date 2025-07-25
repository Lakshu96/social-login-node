# social-login-node

A Node.js service for handling social login via Google and Apple.

## Features

- Google OAuth2 login
- Apple Sign In (with private email relay support)
- User creation and lookup logic
- Token validation and error handling

## Requirements

- Node.js >= 20.9.0
- npm >= 9.0.0

## Installation

```bash
git clone https://github.com/Lakshu96/social-login-node.git
cd social-login-node
npm install
```

## Environment Variables

Create a `.env` file in the root directory and set the following variables:

```env
GOOGLE_CLIENT_ID=your-google-client-id
APPLE_CLIENT_ID=your-apple-client-id
APPLE_TEAM_ID=your-apple-team-id
APPLE_KEY_ID=your-apple-key-id
```

## Additional Setup

- Place your Apple private key file as `key.p8` in the project root.

## Usage

You can import and use the service in your Node.js application:

```js
const socialLoginService = require("./social-login-service");

// Example: Validate a Google token
const userData = await socialLoginService.validateToken(
  "google",
  googleIdToken,
  { fcmToken: "...", language: "en" }
);

// Example: Validate an Apple token
const userData = await socialLoginService.validateToken("apple", appleIdToken, {
  user: appleUserJson,
  fcmToken: "...",
  language: "en",
});
```

## Methods

- `validateToken(provider, token, additionalData)`: Main entry for validating social login tokens.
- `findOrCreateUser(socialData)`: Finds or creates a user based on social login data.

## Error Handling

The service returns structured error responses for:

- Expired tokens
- Invalid signatures
- Tokens used before/after valid time
- Apple private relay email detection
