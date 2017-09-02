const axios = require('axios');
const errors = require('feathers-errors');
module.exports = (socialId, socialToken) => {
    return new Promise(async(resolve, reject) => {
        let socialAuth = await axios.get(`https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=${socialToken}`);
        socialAuth = socialAuth.data;
// if 'sub' key does not exists, auth fails
        if (!socialAuth.hasOwnProperty('sub')) {
            reject(new errors.BadRequest('Invalid Social Token.', {socialToken}));
        }
if (socialAuth.sub != socialId) {
            reject(new errors.BadRequest('Social Token does not match Social Id.', {socialToken, socialId}));
        }
        resolve(true);
    });
}