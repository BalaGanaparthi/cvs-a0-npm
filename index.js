
/**
 * 
 */

const a0MgmtClient = require('auth0').ManagementClient;
const jwt = require('jsonwebtoken');
const { v4: uuid } = require('uuid');
const rp = require("request-promise");

//
const cache_key_token_prefix = "TOKEN_"
//
const token_key_token = "token"
const token_key_expiry = "expiry"
//
const client_key_client_id = "client_id"
const client_key_client_type = "client_type"
const client_key_client_creds = "client_creds"
const const_client_creds_type_secret_key = "secret_key"
const const_client_creds_type_pvt_key_jwt = "private_key_jwt"
//
const secret_key_domain = "DOMAIN"
const secret_key_this_action_name = "THIS_ACTION_NAME"
const secret_key_apis = "ENTERPRISE_APIs"
const secret_key_token_prefix = "TOKEN_"
const secret_key_client_prefix = "CLIENT_"

/**
 * Iterate through the APIs and check for tokens in secrets
 * > If valid tokens already exists, then reuse the tokens
 * > If tokens do not exist or have expired then mint new tokens
 * 
 * Add the tokens to cache 
 * 
 * @param {*} event 
 * @param {*} api 
 */
async function loadTokensToCache(event, api) {

    const domain = event.secrets[secret_key_domain]
    const apis = getAPIs(event);

    ////Get existing secrets in the action : [{name: '', value: ''},{}...]
    const secrets = Object.entries(event.secrets).map(([name, value]) => ({ name, value }));

    const a0Domain = `https://${domain}/`
    const tokenEndpoint = `https://${domain}/oauth/token`

    let tokensMinted = false;

    for (let i = 0; i < apis.length; i++) {

        const apiName = apis[i].name;
        const apiAudience = apis[i].aud;

        const apiTokenJsonString = event.secrets[`${secret_key_token_prefix}${apiName}`]
        const apiToken = convertStringLiteralToJsonObj(apiTokenJsonString)

        if (isTokenValidForAPI(apiToken)) {
            //Cache Token
            api.cache.set(`${cache_key_token_prefix}${apiName}`, apiToken[token_key_token])
        } else {
            //Mint Token

            //Generate a signed jwt
            const apiClientDetailsJsonString = event.secrets[`${secret_key_client_prefix}${apiName}`]
            const apiClientDetails = convertStringLiteralToJsonObj(apiClientDetailsJsonString)
            const clientID = apiClientDetails[client_key_client_id]
            const credsType = apiClientDetails[client_key_client_type]

            let token
            if (credsType === const_client_creds_type_secret_key) {
                const clientSecret = apiClientDetails[client_key_client_creds]
                token = getAccesTokenWithClientSecret(tokenEndpoint, clientID, clientSecret, apiAudience)
            } else if (credsType === const_client_creds_type_pvt_key_jwt) {
                const privateKey = apiClientDetails[client_key_client_creds]
                const jwtAssertion = createAssertion(clientID, privateKey, a0Domain)
                token = getAccesTokenWithPvtKeyJwt(tokenEndpoint, jwtAssertion, apiAudience)

            }
            updSecretAndCacheToken(api, token, apiName,  secrets)
            if(!tokensMinted){
                tokensMinted = true
            }
        }
    }
    if(tokensMinted){
        const actionName = event.secrets[secret_key_this_action_name]
        deployActionWithSecrets(secrets, actionName)
    }
}

/**
 * Get the ENT API JSON string from the action secrets and return JSON object
 * 
 * @param {*} event 
 * @returns {jsonObj} 
 */
async function getAPIs(event) {
    const enterprise_apis_json = event.secrets[secret_key_apis]
    return convertStringLiteralToJsonObj(enterprise_apis_json)
}

/**
 * Convert JSON formatted string literal to JSON Object
 * 
 * @param {String} jsonStringLiteral 
 */
async function convertStringLiteralToJsonObj(jsonStringLiteral) {
    return jsonStringLiteral ? JSON.parse(jsonStringLiteral) : {}
}

/**
 * Check if the access token for an API is valid
 * 
 * Name = TOKEN_{Ent-API.name}
 * Value = {"at" : {AccessToken}, "expiry" : "expires-In-millis"}
 * 
 * @param {*} event 
 * @param {*} apiName 
 */
async function isTokenValidForAPI(apiToken) {
    var isTokenValid
    if (!isEmptyJSON(apiToken)) {
        const apiToken = apiToken[token_key_token]
        if (apiToken) {
            const tokenExpiry = apiToken[token_key_expiry]
            if (apiToken) {
                isTokenValid = Number(enterprise_api_token_expiry) > Date.now()
            } else {
                isTokenValid = false
            }
        } else {
            isTokenValid = false
        }
    } else {
        isTokenValid = false
    }
    return isTokenValid;
}

/**
 * 
 * @param {*} jsonObj 
 * @returns {boolean} true : if JSON object is empty `{}`
 */
async function isEmptyJSON(jsonObj) {
    return Object.keys(jsonObj).length === 0;
}

async function updSecretAndCacheToken(api, token, apiName, secrets) {

    //Set token in Secrets
    secrets.push({
        name: `${secret_key_token_prefix}${apiName}`,
        value: `{"${token_key_token}" : "${token.access_token}", "${token_key_expiry}" : "${String(Date.now() + (982 * token.expires_in))}"}`
    });

    //Cache the enterprise access token
    api.cache.set(`${cache_key_token_prefix}${apiName}`, accessToken)

}

/**
 * Function to redeem signed jwt for tokens (management and enterprise apis)
 * 
 * @param {*} jwtAssertion - Signed JWT
 * @param {*} audience - API identifier
 * @returns - Return access token and the token expiry : 
 *            {access_token: 'At', expires_in : 'AT Expiry' }
 */
async function getAccesTokenWithPvtKeyJwt(tokenEndpoint, jwtAssertion, audience) {
    const auth0LoginOpts = {
        url: tokenEndpoint,
        method: "POST",
        json: true,
        body: {
            grant_type: "client_credentials",
            client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            client_assertion: jwtAssertion,
            audience: audience
        }
    };

    return _getAccesToken(auth0LoginOpts)
}

async function getAccesTokenWithClientSecret(tokenEndpoint, clientID, clientSecret, audience) {
    const auth0LoginOpts = {
        url: tokenEndpoint,
        method: "POST",
        json: true,
        body: {
            grant_type: "client_credentials",
            client_id: clientID,
            client_secret: clientSecret,
            audience: audience
        }
    };

    return _getAccesToken(auth0LoginOpts)
}

async function _getAccesToken(tokenRequestPayload) {
    let auth0LoginBody
    try {
        auth0LoginBody = await rp(tokenRequestPayload);
    } catch (error) {
        console.error('Error getting token : ', error.message);
    }
    return (auth0LoginBody)
        ? { access_token: auth0LoginBody.access_token, expires_in: auth0LoginBody.expires_in }
        : { access_token: "", expires_in: "" };
}