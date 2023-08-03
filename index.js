
const ManagementClient = require('auth0').ManagementClient;
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
const client_key_client_creds_type = "creds_type"
const client_key_client_creds = "client_creds"
const const_client_creds_type_secret_key = "secret_key"
const const_client_creds_type_pvt_key_jwt = "private_key_jwt"
//
const secret_key_domain = "DOMAIN"
const secret_key_this_action_name = "THIS_ACTION_NAME"
const secret_key_apis = "ENTERPRISE_APIs"
const secret_key_token_prefix = "ent_api_token_"
const secret_key_client_prefix = "ENT_API_CLIENT_"
const secret_key_mgmt_api_client = "MGMT_API_CLIENT"
const secret_key_mgmt_api_token = "mgmt_api_token"
const secret_key_debug = "DEBUG"

var debug = false

function helloA0(event, api) {
    console.log(`${JSON.stringify(event)} ${JSON.stringify(api)}`)
    return event.secrets
}

/**
 * <exported>
 * 
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

    let debug = Object.keys(event.secrets).includes(secret_key_debug);

    _log("loadTokensToCache", "Start")

    const domain = event.secrets[secret_key_domain]
    const apis = getAPIs(event);

    ////Get existing secrets in the action : [{name: '', value: ''},{}...]
    const secrets = Object.entries(event.secrets).map(([name, value]) => ({ name, value }));
    console.log(`loadTokensToCache :: secrets = [${JSON.stringify(secrets) }]`)
    const a0Domain = `https://${domain}/`
    const tokenEndpoint = `https://${domain}/oauth/token`

    let tokensMinted = false;

    for (let i = 0; i < apis.length; i++) {

        const apiName = apis[i].name;
        const apiAudience = apis[i].aud;
        
        const apiTokenJsonString = event.secrets[`${secret_key_token_prefix}${apiName}`]
        const apiToken = convertStringLiteralToJsonObj(apiTokenJsonString)

        console.log(`loadTokensToCache :: secret value for key [${secret_key_token_prefix}${apiName}] = [${apiTokenJsonString}] \n\t token = [${JSON.stringify(apiToken[token_key_token])}]\n\t expiry = [${JSON.stringify(apiToken[token_key_expiry])}]`)

        if (isTokenValidForAPI(apiToken)) {
            //Cache Token
            api.cache.set(`${cache_key_token_prefix}${apiName}`, apiToken[token_key_token])
        } else {
            //Mint Token

            //Generate a signed jwt
            const apiClientDetailsJsonString = event.secrets[`${secret_key_client_prefix}${apiName}`]
            const apiClientDetails = convertStringLiteralToJsonObj(apiClientDetailsJsonString)
            const clientID = apiClientDetails[client_key_client_id]
            const credsType = apiClientDetails[client_key_client_creds_type]

            let token
            if (credsType === const_client_creds_type_secret_key) {
                const clientSecret = apiClientDetails[client_key_client_creds]
                token = await getAccesTokenWithClientSecret(tokenEndpoint, clientID, clientSecret, apiAudience)
            } else if (credsType === const_client_creds_type_pvt_key_jwt) {
                const privateKey = apiClientDetails[client_key_client_creds]
                const jwtAssertion = createAssertion(clientID, privateKey, a0Domain)
                token = await getAccesTokenWithPvtKeyJwt(tokenEndpoint, jwtAssertion, apiAudience)
            }
            _log("loadTokensToCache", `APIName = [${apiName}], ClientID = [${clientID}, CredsType = [${credsType}], Token = [${token}]`)
            console.log(`loadTokensToCache :: APIName = [${apiName}], ClientID = [${clientID}], CredsType = [${credsType}], Token = [${JSON.stringify(token)}]`)

            updSecretAndCacheToken(api, token, apiName, secrets)
            if (!tokensMinted) {
                tokensMinted = true
            }
        }
    }
    if (tokensMinted) {
        const actionName = event.secrets[secret_key_this_action_name]
        await deployActionWithUpdatedSecrets(event, tokenEndpoint, secrets, domain, actionName)
    }
    _log("loadTokensToCache", "End")
}

/**
 * Get the API JSON string from the action secrets and return JSON object
 * 
 * @param {*} event 
 * @returns {jsonObj} 
 */
function getAPIs(event) {
    _log("getAPIs", "Start")
    const apis_json = event.secrets[secret_key_apis]
    const apis_json_obj = convertStringLiteralToJsonObj(apis_json)
    _log("getAPIs", "End")
    return apis_json_obj
}

/**
 * Convert JSON formatted string literal to JSON Object
 * 
 * @param {String} jsonStringLiteral 
 */
function convertStringLiteralToJsonObj(jsonStringLiteral) {
    _log("convertStringLiteralToJsonObj", "Start")
    const json_obj = jsonStringLiteral ? JSON.parse(jsonStringLiteral) : {}
    _log("convertStringLiteralToJsonObj", "End")
    return json_obj
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
function isTokenValidForAPI(apiToken) {
    _log("isTokenValidForAPI", "Start")
    var isTokenValid
    if (!isEmptyJSON(apiToken)) {
        const _apiToken = apiToken[token_key_token]
        if (_apiToken) {
            const _tokenExpiry = apiToken[token_key_expiry]
            console.log(`\t> isTokenValidForAPI :: Token Expiry ${_tokenExpiry} `)
            if (_tokenExpiry) {
                isTokenValid = Number(_tokenExpiry) > Date.now()
                console.log(`\t> isTokenValidForAPI :: Number(_tokenExpiry) = ${Number(_tokenExpiry)} `)
                console.log(`\t> isTokenValidForAPI :: Date.now() = ${Date.now()} `)
                console.log(`\t> isTokenValidForAPI :: isTokenValid ${isTokenValid} `)
            } else {
                isTokenValid = false
                console.log(`\t> isTokenValidForAPI :: No [${token_key_expiry}] key in token json`)
            }
        } else {
            isTokenValid = false
            console.log(`\t> isTokenValidForAPI :: No [${token_key_token}] key in token json`)
        }
    } else {
        isTokenValid = false
        console.log(`\t> isTokenValidForAPI :: token is empty`)
    }
    console.log(`\t> isTokenValidForAPI :: token ${isTokenValid ? "is" : "is not"} valid`)
    _log("isTokenValidForAPI", "End")
    return isTokenValid;
}

/**
 * 
 * @param {*} jsonObj 
 * @returns {boolean} true : if JSON object is empty `{}`
 */
function isEmptyJSON(jsonObj) {
    _log("isEmptyJSON", "Start")
    const isEmpty = Object.keys(jsonObj).length === 0;
    console.log(`\t> isEmptyJSON :: jsonObj ${isEmpty ? "is" : "is not"} empty`)
    _log("isEmptyJSON", "End")
    return isEmpty
}

/**
 * function to generate signed JWT. 
 * 
 * @param {*} clientID - Client ID of the M2M app in Auth0 configured with Private Key credentials
 * @param {*} privateKey - Associated private key with the public key set with M2M app
 * @param {*} a0Domain - Auth0 domain
 * @returns - Signed JWT assertions
 */
function createAssertion(clientID, privateKey, domain) {
    _log("createAssertion", "Start")
    const pk = privateKey.split("\\n").join("\n");
    var signOptions = {
        issuer: clientID,
        subject: clientID,
        audience: domain,
        expiresIn: "60s",
        algorithm: "RS256",
        jwtid: uuid(),
        header: { "alg": "RS256" }
    };
    var token = jwt.sign({}, pk, signOptions);
    _log("createAssertion", "End")
    return token;
}

/**
 * Update existing secrets with new token and cache the new token
 * 
 * @param {*} api 
 * @param {*} token 
 * @param {*} apiName 
 * @param {*} secrets 
 */
function updSecretAndCacheToken(api, token, apiName, secrets) {
    _log("updSecretAndCacheToken", "Start")
    //Set token in Secrets
    secrets.push({
        name: `${secret_key_token_prefix}${apiName}`,
        value: `{"${token_key_token}" : "${token.access_token}", "${token_key_expiry}" : "${String(Date.now() + (982 * token.expires_in))}"}`
    });

    //Cache the enterprise access token
    api.cache.set(`${cache_key_token_prefix}${apiName}`, token.access_token)
    _log("updSecretAndCacheToken", "End")
}

/**
 * Function to mint token with private_key_jwt
 * 
 * @param {*} jwtAssertion - Signed JWT
 * @param {*} audience - API identifier
 * @returns - Return access token and the token expiry : 
 *            {access_token: 'At', expires_in : 'AT Expiry' }
 */
async function getAccesTokenWithPvtKeyJwt(tokenEndpoint, jwtAssertion, audience) {
    _log("getAccesTokenWithPvtKeyJwt", "Start")
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
    const token = await _getAccesToken(auth0LoginOpts);
    _log("getAccesTokenWithPvtKeyJwt", "End")
    return token
}

/**
 * function to mint token with client_secret
 * 
 * @param {*} tokenEndpoint 
 * @param {*} clientID 
 * @param {*} clientSecret 
 * @param {*} audience 
 * @returns - Return access token and the token expiry : 
 *            {access_token: 'At', expires_in : 'AT Expiry' }
 */
async function getAccesTokenWithClientSecret(tokenEndpoint, clientID, clientSecret, audience) {
    _log("getAccesTokenWithClientSecret", "Start")
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
    // console.log(`getAccesTokenWithClientSecret :: Calling _getAccesToken with payload > [${JSON.stringify(auth0LoginOpts)}]`)
    const token = await _getAccesToken(auth0LoginOpts)
    // console.log(`getAccesTokenWithClientSecret :: Token > [${JSON.stringify(token)}]`)

    _log("getAccesTokenWithClientSecret", "End")
    return token
}

async function _getAccesToken(tokenRequestPayload) {
    _log("_getAccesToken", "Start")

    // console.log(`_getAccesToken :: tokenRequestPayload = [${JSON.stringify(tokenRequestPayload)}]`)

    let auth0LoginBody
    try {
        auth0LoginBody = await rp(tokenRequestPayload)
    } catch (error) {
        console.error('_getAccesToken :: Error getting token : ', error.message);
    }

    // console.log(`_getAccesToken :: response from token endpoint : [${JSON.stringify(auth0LoginBody)}]`)

    // const token = (auth0LoginBody)
    //     ? { access_token: auth0LoginBody.access_token, expires_in: auth0LoginBody.expires_in }
    //     : { access_token: "", expires_in: "" };
    _log("_getAccesToken", "End")
    return auth0LoginBody
}

async function deployActionWithUpdatedSecrets(event, tokenEndpoint, secrets, domain, actionName) {
    _log("deployActionWithUpdatedSecrets", "Start")

    const mgmtApiTokenJsonString = event.secrets[secret_key_mgmt_api_token]
    console.log(`\t> deployActionWithUpdatedSecrets :: mgmtApiTokenJsonString? > [${mgmtApiTokenJsonString}]`)
    const mgmtApiToken = convertStringLiteralToJsonObj(mgmtApiTokenJsonString)

    const audience = `https://${domain}/api/v2/`

    let token
    if (isTokenValidForAPI(mgmtApiToken)) {
        token = mgmtApiToken[token_key_token]
        console.log(`\t> deployActionWithUpdatedSecrets :: found management access token ${mgmtApiToken}`)
    } else {
        console.log(`deployActionWithUpdatedSecrets :: need to mint MGMT Token`)
        //Generate a signed jwt
        const mgmtApiClientDetailsJSON = event.secrets[secret_key_mgmt_api_client]
        // console.log(`deployActionWithUpdatedSecrets :: mgmtApiClientDetailsJSON > [${mgmtApiClientDetailsJSON}]`)
        const mgmtApiClientDetails = convertStringLiteralToJsonObj(mgmtApiClientDetailsJSON)
        const clientID = mgmtApiClientDetails[client_key_client_id]
        const credsType = mgmtApiClientDetails[client_key_client_creds_type]

        if (credsType === const_client_creds_type_secret_key) {
            const clientSecret = mgmtApiClientDetails[client_key_client_creds]
            const _token = await getAccesTokenWithClientSecret(tokenEndpoint, clientID, clientSecret, audience)
            token = _token.access_token
        } else if (credsType === const_client_creds_type_pvt_key_jwt) {
            const privateKey = mgmtApiClientDetails[client_key_client_creds]
            const jwtAssertion = createAssertion(clientID, privateKey, domain)
            const _token =  await getAccesTokenWithPvtKeyJwt(tokenEndpoint, jwtAssertion, audience)
            token = _token.access_token
        }

        // console.log(`deployActionWithUpdatedSecrets :: Management token body is [${JSON.stringify(token)}] `)
        secrets.push({
            name: secret_key_mgmt_api_token,
            value: `{"${token_key_token}" : "${token.access_token}", "${token_key_expiry}" : "${String(Date.now() + (982 * token.expires_in))}"}`
        });

        console.log(`\t> deployActionWithUpdatedSecrets :: Secrets object to be store in A0 is [${JSON.stringify(secrets)}] `)
    }

    const managementAPIHandle = new ManagementClient({
        token: token.access_token,
        domain: domain,
        scope: "read:actions update:actions"
    });

    try {
        //Get the actionId by actionName
        const actionId = await getActionID(actionName, managementAPIHandle);
        var params = { id: actionId };

        const _secrets = { secrets: secrets }
        //Update the action with the secrets
        managementAPIHandle.actions.update(params, _secrets);

        //Deploy action
        managementAPIHandle.actions.deploy(params);
        console.log(`\t > deployActionWithUpdatedSecrets :: Acton is deployed`)

    } catch (error) {
        console.error('\t Error updating secrets:', error.message);
    }

    _log("deployActionWithUpdatedSecrets", "End")
}

/**
   * function to get action_id by action_name
   * 
   * @param {*} actionName - Name of action (to update the secrets with AT and ATExpiry)
   * @param {*} management - Management api handle to call Auth0 to get action_id
   * @returns - action_id ("0" if any error or a valid action_id)
   */
async function getActionID(actionName, managementAPIHandle) {
    _log("getActionID", "Start")
    // console.log(`getActionID :: ActionName is ${actionName} `)
    let actionId = "0"
    try {
        const params = { actionName: actionName };
        const actions = await managementAPIHandle.actions.getAll(params);
        const action = actions.actions.find((action) => action.name === actionName);
        if (action) {
            actionId = action.id;
        }
    } catch (error) {
        console.error('Error retrieving actions:', error.message);
    }
    // console.log(`getActionID :: ActionID is ${actionId}`)
    _log("getActionID", "End")
    return actionId;
}

function _log(method, message) {
    // console.log(`Debug is ${debug ? "on." : "off."}\n`)
    // if (debug) {
        console.log(`[${method}]>> [${message}]`)
    // }
}

module.exports = {
    loadTokensToCache: loadTokensToCache,
    helloA0: helloA0
}