const { OAuth2Client } = require('google-auth-library');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const crypto = require('crypto');
const _User = require('../resources/v1/users/user.model');
// const _User = new UsersResource();
const DataHelper = require('../helpers/v1/data.helpers')
const _DataHelper = new DataHelper()
const fs = require('fs');
const privateKey = fs.readFileSync('./key.p8', 'utf8');
const { faker } = require('@faker-js/faker');

class SocialLoginService {
    constructor() {
        this.googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
        this.randomFirstname = faker.person.firstName();
        this.randomLastName = faker.person.lastName();

        this.randomEmail = faker.internet.email({
            firstName: this.randomFirstname,
            lastName: this.randomLastName
        });
        this.appleConfig = {
            clientId: process.env.APPLE_CLIENT_ID,
            teamId: process.env.APPLE_TEAM_ID,
            keyId: process.env.APPLE_KEY_ID,
            privateKey: privateKey
        };
        console.log(this.randomFirstname, this.randomLastName, this.randomEmail);

    }
    async generateRandomEmail() {
        return this.randomEmail;
    }
    async generateRandomFirstName() {
        return this.randomFirstname;
    }
    async generateRandomLastName() {
        return this.randomLastName;
    }

    /**
     * Main social login function
     * @param {string} provider - 'google' or 'apple'
     * @param {string} token - ID token from the provider
     * @param {Object} additionalData - Any additional data (e.g., Apple authorization code)
     * @returns {Object} User data
     */
    // MARK:validateToken
    async validateToken(provider, token, additionalData = {}) {
        try {
            let userData;

            switch (provider.toLowerCase()) {
                case 'google':
                    userData = await this.handleGoogleLogin(token, additionalData);
                    break;
                case 'apple':
                    userData = await this.handleAppleLogin(token, additionalData);
                    break;
                default:
                    throw new Error(`Unsupported provider: ${provider}`);
            }

            return userData;

        } catch (error) {
            throw new Error(`${provider} authentication failed: ${error.message}`);
        }
    }

    /**
     * Handle Google OAuth login
     * @param {string} idToken - Google ID token
     * @returns {Object} User data
     */

    // MARK:Handle Google Login
    async handleGoogleLogin(idToken, additionalData = {}) {
        try {
            const ticket = await this.googleClient.verifyIdToken({
                idToken: idToken,
                audience: process.env.GOOGLE_CLIENT_ID
            });

            const payload = ticket.getPayload();

            // Check if token is expired
            const now = Math.floor(Date.now() / 1000);
            if (payload.exp < now) {
                return {
                    response_type: "expire_token",
                    response_message: "Google token has expired"
                }
            }

            return {
                socialId: payload.sub,
                email: payload.email,
                emailVerified: payload.email_verified,
                name: payload.name,
                firstName: payload.given_name,
                lastName: payload.family_name,
                picture: payload.picture,
                provider: 'google',
                fcm_token: additionalData.fcmToken,
                language: additionalData.language
            };

        } catch (error) {
            if (error.message.includes('Token used too early')) {
                return {
                    response_type: "used_before_time",
                    response_message: "Google token used before valid time"
                }
            }
            if (error.message.includes('Invalid token signature')) {
                return {
                    response_type: "invalid_sign",
                    response_message: "Invalid Google token signature"
                }
            }
            if (error.message.includes('Token used too late')) {
                return {
                    response_type: "invalid_after_time",
                    response_message: "Token used too late"
                }
            }
            return {
                response_type: "invalid",
                response_message: error.message
            }

        }
    }

    /**
     * Handle Apple Sign In
     * @param {string} identityToken - Apple identity token
     * @param {Object} additionalData - Authorization code, user info, etc.
     * @returns {Object} User data
     */
    // MARK: Handle Apple Login
    async handleAppleLogin(identityToken, additionalData = {}) {
        try {
            const decoded = await this.verifyAppleToken(identityToken);

            if (decoded?.response_type == "invalid") {
                return {
                    response_type: decoded.response_type,
                    response_message: decoded.response_message
                }
            }

            let userData = {
                socialId: decoded.sub,
                email: decoded.email ?? await this.generateRandomEmail(),
                emailVerified: decoded.email_verified === 'true',
                provider: 'apple',
                fcm_token: additionalData.fcmToken,
                language: additionalData.language
            };

            // Apple only provides name and email on first sign-in
            if (additionalData.user) {
                const userInfo = typeof additionalData.user === 'string'
                    ? JSON.parse(additionalData.user)
                    : additionalData.user;

                userData.name = userInfo.name ?
                    `${userInfo.name.firstName || ''} ${userInfo.name.lastName || ''}`.trim() : null;
                userData.firstName = userInfo.name?.firstName || null;
                userData.lastName = userInfo.name?.lastName || null;
            }

            // Handle private email relay
            if (userData.email && userData.email.includes('@privaterelay.appleid.com')) {
                userData.isPrivateEmail = true;
            }

            return userData;

        } catch (error) {
            throw error;
        }
    }

    /**
     * Verify Apple identity token
     */
    // MARK: Verify Apple Token
    async verifyAppleToken(identityToken) {
        try {
            const appleKeys = await this.getApplePublicKeys();

            const header = jwt.decode(identityToken, { complete: true }).header;
            const key = appleKeys.find(k => k.kid === header.kid);

            if (!key) {
                throw new Error('Apple public key not found');
            }

            const publicKey = this.createPublicKey(key);
            const decoded = jwt.verify(identityToken, publicKey, {
                algorithms: ['RS256'],
                audience: this.appleConfig.clientId,
                issuer: 'https://appleid.apple.com'
            });

            return decoded;

        } catch (error) {
            if (error.name === 'TokenExpiredError') {
                return {
                    response_type: "invalid",
                    response_message: "Apple token has expired"
                }
            }
            if (error.name === 'JsonWebTokenError') {
                return {
                    response_type: "invalid",
                    response_message: "Invalid Apple token"
                }
            }
            throw error;
        }
    }

    /**
     * Get Apple's public keys
     */

    // MARK: Get Apple Public Keys
    async getApplePublicKeys() {
        try {
            const response = await axios.get('https://appleid.apple.com/auth/keys', {
                timeout: 10000
            });
            return response.data.keys;
        } catch (error) {
            throw new Error('Failed to fetch Apple public keys');
        }
    }

    /**
     * Create public key from Apple's JWK
     */

    // MARK: Create Public Key
    createPublicKey(key) {
        const { n, e } = key;
        // const nBuffer = Buffer.from(n, 'base64url');
        // const eBuffer = Buffer.from(e, 'base64url');

        const publicKey = crypto.createPublicKey({
            key: {
                kty: 'RSA',
                n: n,
                e: e
            },
            format: 'jwk'
        });

        return publicKey.export({ format: 'pem', type: 'spki' });
    }

    /**
     * Find or create user from social login data
     * @param {Object} socialData - Social login user data
     * @returns {Object} User object
     */

    // MARK: Find Or Create User
    async findOrCreateUser(socialData) {
        // Try to find the user by email first
        let user = await _User.findOne({
            where: { email: socialData.email, role_id: 2 }
        });

        if (user) {
            // Update social login info if user exists
            await _User.update(
                {
                    provider_id: socialData.socialId,
                    profile_picture: socialData.picture || user.profile_picture,
                    language: socialData.language,
                    email_verified_at: socialData.emailVerified && !user.email_verified_at ? new Date() : user.email_verified_at
                },
                {
                    where: { id: user.id }
                }
            );

            return await _User.findOne({ where: { id: user.id } });
        }

        // If not found by email, try to find by social provider ID
        user = await _User.findOne({
            where: { provider_id: socialData.socialId }
        });

        if (user) {
            // Update email if changed on the social provider
            if (user.email !== socialData.email) {
                await _User.update(
                    {
                        email: socialData.email,
                        email_verified_at: socialData.emailVerified ? new Date() : null
                    },
                    {
                        where: { id: user.id }
                    }
                );
            }

            return await _User.findOne({ where: { id: user.id } });
        }
        let password = await _DataHelper.generateRandomPassword();
        let hashedPassword = await _DataHelper.hashPassword(password);
        // Create a new user if none found

        const newUserData = {
            email: socialData.email,
            first_name: socialData.firstName,
            last_name: socialData.lastName,
            profile_photo: socialData.picture,
            provider_id: socialData.socialId,
            provider: socialData.provider,
            fcm_token: socialData.fcm_token,
            email_verified_at: socialData.emailVerified ? new Date() : null,
            language: socialData.language,
            created_at: new Date(),
            updated_at: new Date()
        };

        console.log("Creating user:", newUserData.email);

        const createdUser = await _User.create(newUserData);
        return await _User.findOne({ where: { id: createdUser.id } });
    }
}

module.exports = new SocialLoginService();