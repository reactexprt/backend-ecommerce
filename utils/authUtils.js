const { google } = require('googleapis');
const OAuth = require('../models/OAuth');


// Function to update the refresh token in the database
async function updateStoredRefreshToken(service, newRefreshToken) {
    await OAuth.findOneAndUpdate(
        { service },
        { refreshToken: newRefreshToken },
        { new: true, upsert: true }
    );
}

// Function to retrieve the refresh token from your database
async function getStoredRefreshToken(service) {
    const oauthRecord = await OAuth.findOne({ service });
    if (!oauthRecord) {
        throw new Error('No refresh token found for this service');
    }
    return oauthRecord.refreshToken;
}

// Function to get a new access token using the refresh token
async function updateExpiredRefreshToken() {
    try {
        const refreshToken = await getStoredRefreshToken('google');
        const oAuth2Client = new google.auth.OAuth2(
            process.env.CLIENT_ID,
            process.env.CLIENT_SECRET,
            'http://localhost'
        );

        oAuth2Client.setCredentials({
            refresh_token: refreshToken,
        });

        // Get a new access token
        const { res } = await oAuth2Client.getAccessToken();
        const newRefreshToken = res.data.refresh_token;

        // Check if a new refresh token is provided (Google may rotate refresh tokens)
        if (!!newRefreshToken) {
            await updateStoredRefreshToken('google', newRefreshToken);
        }

        return newRefreshToken || '';

    } catch (error) {
        if (error.response && error.response.status === 401) {
            console.error('Refresh token is invalid or expired. User needs to re-authenticate.');
            // Prompt user to re-authenticate or handle the situation as needed
        } else {
            console.error('Failed in refreshing refresh token:');
            throw error;
        }
    }
}

module.exports = {
    updateExpiredRefreshToken,
    getStoredRefreshToken
};