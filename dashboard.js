const express = require('express');
const app = express();
const axios = require('axios');
const _ = require('lodash');
const formurlencoded = require('form-urlencoded');
const cookieParser = require('cookie-parser');
//const bodyParser = require('body-parser');
const jwt_decode = require('jwt-decode');
const jwt = require('jsonwebtoken');
const jwkToPem = require('jwk-to-pem');
//const _ = require('lodash');
const favicon = require('serve-favicon');
const path = require('path');
const e = require('express');
const { access, accessSync } = require('fs');
const { info } = require('console');
const multer = require("multer");
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });
const md5 = require('md5');

//Grill Modes
const STARTUP_MODE = 0;
const STANDBY_MODE = 1;
const RUN_MODE = 2;
const FEED_MODE = 3;
const SHUTDOWN_MODE = 4;
const RESET_MODE = 5;
const FAN_MODE = 6;


const admin_api_token = 'iJ6UxPXpdA1IVaXcMSiV18IDob3JGKSc4W7EYChV';

const HTTP_REDIRECT_RESPONSE_CODE = 301;
const COGNITO_POOL_ID = 'us-west-2_6pjAdMAdn';
const COGNITO_JWT_ISS = 'https://cognito-idp.us-west-2.amazonaws.com/us-west-2_6pjAdMAdn'; //Compare this to JWT (ISS) 

const COGNITO_DASHBOARD_APP_CLIENT_ID = '1ki52sug4ijcl7t0hij4rq4j8d';
const COGNITO_DASHBOARD_CALLBACK_URL = 'https://iot.campchef.site/v3';
const COGNITO_DASHBOARD_DOMAIN = 'https://campchef.auth.us-west-2.amazoncognito.com';
const DASHBOARD_COGNITO_LOGIN_URL = `${COGNITO_DASHBOARD_DOMAIN}/login?response_type=code&client_id=${COGNITO_DASHBOARD_APP_CLIENT_ID}&redirect_uri=${COGNITO_DASHBOARD_CALLBACK_URL}`;
const DASHBOARD_COGNITO_LOGOUT_URL = `${COGNITO_DASHBOARD_DOMAIN}/logout?response_type=code&client_id=${COGNITO_DASHBOARD_APP_CLIENT_ID}&redirect_uri=${COGNITO_DASHBOARD_CALLBACK_URL}`;
const COGNITO_TOKEN_ENDPOINT = 'https://campchef.auth.us-west-2.amazoncognito.com/oauth2/token';


let COGNITO_JWK = { "keys": [{ "alg": "RS256", "e": "AQAB", "kid": "l6DlNF5gb0yDGI/3W7uM8qyT3dkG/uGyjlAUMRFlIG8=", "kty": "RSA", "n": "rJqyNXPOjNLJ3qxXZrFAuPLT_VstRHPnAh1kIHly4De1p9ucoDi-2crZmBmMYTIs1Fu270KwTglReT4WfoyCpu8NdoJShP40L39BKMidb9Dcj6kIj-9Wx27dkNqSu2iaPGq0cOuALG6H1_WkY6GjCVi1bU3FJe17RoQtb_AMNKMEowiIVEXMl1yLRzRPRQb6IOaXwmnHuwiIuTJm-YJvGNN88tF1hWoyiPyVS8sWXBjW90vuhkx4XwFqQZRy3hF8J3zFeT1ow-5FcS5jV0OpSs3b4HWm6KYd47sHB20ecnIon4xyMstkyYBKtEuI6e2ubo5q9ij_1Y4SNf8GcMU2Tw", "use": "sig" }, { "alg": "RS256", "e": "AQAB", "kid": "YymdEmRCwSYLdlRKdM3cfS9HfgIDESfWIFx18+ZDQok=", "kty": "RSA", "n": "4SnDKaKMKTqyvF6xfT9mFVp_ACnJCwG27ItX1qZ5E90CyJugrc_eeAfMzl7Itmy-amM5XgF9ayQzOHdEz3m92lJERdEHf627wNLlnBe6a6Xn9PcXwaWljdXtkRphu6R721bpe57DcN678np-2c53nTa-lRNa1r2hBvQtHA38Egj1YyHiD0tedHFp_3BHZA5mgf-0WchZUfVKqSsa2ver0PaETIRzXT-VntMMnGSa9zyT9FvOjqzMggLdrAAidyqYNkQPyRpBX4x0EhC0bUHX3FTFIAF7bqvt0eCpoQip8kEYKx5BbH-uhW3z4HNZApn4eZgVxw3tulht0NL8nZVaLQ", "use": "sig" }] }
//JWK kid should match JWT type (in header)
//JWT payload "aud" should match App client Id
//JWT payload "iss" should match user pool "url/poolId"
//Check "token_use" for either "id" or "access"

async function getFaqs() {
    try {
        let config = {};
        config.headers = { 'x-api-key': admin_api_token };
        let faq = await axios.get("https://api.campchef.site/data-v3/faq", config);
        return faq.data.data;
    }
    catch (error) {
        console.log(error);
    }
}

async function getUserDevicesByEmail(email, idToken) {

    //console.log('get devices - id_token: ', idToken);
    try {
        let config = {};
        config.headers = {
            'x-api-key': admin_api_token,
            'Authorization': idToken
        };
        let response = await axios.get(`https://api.campchef.site/device-v3/email/${email}`, config);

        let userInfoDevices = {};
        userInfoDevices.userUUID = response.data.devices.user_uuid;

        let userDevices = [];
        for (key in response.data.devices) {
            //    console.log(key);
            //    console.log(response.data.devices[key]);
            if (key != 'user_uuid') {
                //console.log("push: ", response.data.devices[key]);
                userDevices.push(response.data.devices[key]);
            }
        }

        let onlineUserDevices = [];
        let offlineUserDevices = [];

        //sort by online status
        if (userDevices != undefined && userDevices != null) {
            let numDevices = userDevices.length;
            //    console.log('num devices ', numDevices);
            for (let i = 0; i < numDevices; i++) {
                //console.log(userDevices[i]);
                if (userDevices[i].heartbeat == undefined) {
                    //           console.log('heartbeat undefined: ', i);
                    offlineUserDevices.push(userDevices[i]);
                }
                else {
                    onlineUserDevices.push(userDevices[i]);
                }
            }
        }

        userInfoDevices.userDevices = [...onlineUserDevices, ...offlineUserDevices];
        //   console.log ('length of user InfoDevices array ', userInfoDevices.userDevices.length);

        return userInfoDevices;
    }
    catch (error) {
        console.log(error);
    }
}

async function getUserDevicesByUUID(tokens, userUUID) {
    try {
        let config = {};
        config.headers = {
            'x-api-key': admin_api_token,
            'Authorization': tokens.id_token
        };
        let response = await axios.get(`https://api.campchef.site/device-v3/uuid/${userUUID}`, config);
        //console.log("getDevicesByUUID response: ", response);
        return response.data.devices;
    }
    catch (error) {
        console.log(error);
    }


}

async function getDevicesById(deviceId, tokens) {
    try {
        let config = {};
        config.headers = {
            'x-api-key': admin_api_token,
            'Authorization': tokens.id_token
        };
        let response = await axios.get(`https://api.campchef.site/device-v3/${deviceId}`, config);

        //console.log("getDevicesById response: ", response.data);

        let onlineUserDevices = [];
        let offlineUserDevices = [];

        //sort by online status
        if (response.data.devices != undefined) {
            let numDevices = response.data.devices.length;
            //    console.log('num devices ', numDevices);
            for (let i = 0; i < numDevices; i++) {
                //console.log(userDevices[i]);
                if (response.data.devices[i].heartbeat == undefined) {
                    //           console.log('heartbeat undefined: ', i);
                    offlineUserDevices.push(response.data.devices[i]);
                }
                else {
                    onlineUserDevices.push(response.data.devices[i]);
                }
            }
        }

        response.data.devices = [...onlineUserDevices, ...offlineUserDevices];
        //    console.log ('length of user InfoDevices array ', response.data.devices.length);

        return response.data.devices;

    }
    catch (error) {
        console.log(error);
    }
}

async function getCookedCount(tokens) {
    try {
        let config = {};
        config.headers = {
            'x-api-key': admin_api_token,
            'Authorization': tokens.id_token
        };
        let response = await axios.get(`https://api.campchef.site/data-v3/cookStats`, config);

        //console.log("cook stats response: ", response);
        return response.data;
    }
    catch (error) {
        console.log(error);
    }
}

async function getDeviceCount(tokens) {
    try {
        let config = {};
        config.headers = {
            'x-api-key': admin_api_token,
            'Authorization': tokens.id_token
        };
        let response = await axios.get(`https://api.campchef.site/data-v3/devicecount`, config);

        //console.log("device count response: ", JSON.stringify(response.data.deviceCount[0].count));
        return response.data.deviceCount[0].count;

    }
    catch (error) {
        console.log(error);
    }
}

async function getUserCount(tokens) {
    try {
        let config = {};
        config.headers = {
            'x-api-key': admin_api_token,
            'Authorization': tokens.id_token
        };
        let response = await axios.get(`https://api.campchef.site/data-v3/usercount`, config);

        //console.log("user count response: ", JSON.stringify(response.data.count[0].count));
        return response.data.count[0].count;

    }
    catch (error) {
        console.log(error);
    }
}

async function getTotalGraphUsers(tokens) {
    try {
        let config = {};
        config.headers = {
            'x-api-key': admin_api_token,
            'Authorization': tokens.id_token
        };
        let response = await axios.get(`https://api.campchef.site/data-v3/graph_users/total/`, config);

        //console.log("total graph users: ", response);
        return response.data.users;

    }
    catch (error) {
        console.log(error);
    }

}

async function getESPUpdates(currentWiFiVersion, idToken) {
    try {
        let config = {};
        config.headers = {
            'x-api-key': admin_api_token,
            'Authorization': idToken
        };
        let response = await axios.get(`https://api.campchef.site/ota-v3/esp/${currentWiFiVersion}`, config);
        return response.data;
    }
    catch (error) {
        console.log(error);
    }

}

async function getSTMUpdates(currentMCUversion, model, idToken) {
    try {
        let config = {};
        config.headers = {
            'x-api-key': admin_api_token,
            'Authorization': idToken
        };
        let response = await axios.get(`https://api.campchef.site/ota-v3/stm/${model}/${currentMCUversion}`, config);
        return response.data;
    }
    catch (error) {
        console.log(error);
    }
}

async function getAllVersions(idToken) {
    try {
        let config = {};
        config.headers = {
            'x-api-key': admin_api_token,
            'Authorization': idToken
        };
        let response = await axios.get(`https://api.campchef.site/ota-v3/stm/all/1.1.1`, config);
        return response.data;
    }
    catch (error) {
        console.log(error);
    }
}

async function getDeviceInfo(mac, idToken) {
    //console.log("mac ", mac);
    try {
        let config = {};
        config.headers = {
            'x-api-key': admin_api_token,
            'Authorization': idToken
        };
        let response = await axios.get(`https://api.campchef.site/device-v3/deviceinfo?mac=${mac}`, config);

        //console.log("Got device info response");
        return response.data.deviceInfo;

    }
    catch (error) {
        console.log(error);
    }
}


async function getRedisInfo(idToken) {
    try {
        let config = {};
        config.headers = {
            'x-api-key': admin_api_token,
            'Authorization': idToken
        };
        let response = await axios.get(`https://api.campchef.site/status-v3/redis`, config);

        //    console.log("Got redis info response");
        return response.data;

    }
    catch (error) {
        console.log(error);
    }
}

async function getOnlineDeviceCount(idToken) {
    try {
        let config = {};
        config.headers = {
            'x-api-key': admin_api_token,
            'Authorization': idToken
        };
        let response = await axios.get(`https://api.campchef.site/status-v3/online`, config);

        //  console.log("Got online device count: ", response.data.online);
        return response.data.online;

    }
    catch (error) {
        console.log(error);
    }

}

async function getActiveDevices(idToken) {
    try {
        let config = {};
        config.headers = {
            'x-api-key': admin_api_token,
            'Authorization': idToken
        };
        let response = await axios.get(`https://api.campchef.site/status-v3/active`, config);

        //    console.log("Got active devices: ", response.data.devices);
        return response.data.devices;

    }
    catch (error) {
        console.log(error);
    }

}

function sendControlData(controlData, idToken) {
    return new Promise(async (resolve, reject) => {

        let config = {
            'headers': {
                'Content-Type': 'application/x-www-form-urlencoded',
                'x-api-key': admin_api_token,
                'Authorization': idToken
            }
        };

        let formdata = {};
        formdata.control = controlData;

        try {
            let response = await axios.post('https://api.campchef.site/device-v3/sendcontrol', formdata, config);
            //    console.log('Send Control Data Response: ', response.data);
            resolve(response.data);
        }
        catch (error) {
            console.log(error);
            resolve(error);
        }
    });
}

function sendUpdateInfo(mac, part, updateVersion, idToken) {
    return new Promise(async (resolve, reject) => {

        let config = {
            'headers': {
                'Content-Type': 'application/x-www-form-urlencoded',
                'x-api-key': admin_api_token,
                'Authorization': idToken
            }
        };
        let formdata = {
            'mac': mac,
            'part': part,
            'version': updateVersion
        };
        try {
            let response = await axios.post('https://api.campchef.site/device-v3/updatedevice', formdata, config);
            //    console.log('Send Firmware Update Response: ', response.data);
            resolve(response.data);
        }
        catch (error) {
            console.log(error);
            resolve(error);
        }
    });
}

function uploadFirmware(fileName, fileBuff, md5, idToken) {
    return new Promise(async (resolve, reject) => {

        let config = {
            'headers': {
                'Content-Type': 'application/x-www-form-urlencoded',
                'x-api-key': admin_api_token,
                'Authorization': idToken
            }
        };
        let formdata = {
            'buffer': fileBuff,
            'fileName': fileName,
            'md5': md5
        };
        try {
            let response = await axios.post('https://api.campchef.site/ota-v3/dev/upload', formdata, config);
            console.log('Upload Firmware file Response: ', response.data);
            resolve(response.data);
        }
        catch (error) {
            console.log("firmware upload error: ", error);
            resolve(error);
        }
    });
}

async function getDevFirmwareList(idToken, model = null) {

    try {
        let config = {};
        config.headers = {
            'x-api-key': admin_api_token,
            'Authorization': idToken
        };
        if (model) {
            model = model.toUpperCase();
        }
        let response = await axios.get(`https://api.campchef.site/ota-v3/dev/list?model=${model}`, config);

        // console.log("firmware list: ", response.data.firmwareList);
        return response.data.firmwareList;

    }
    catch (error) {
        console.log(error);
    }
}

function getCognitoToken(code) {
    return new Promise(async (resolve, reject) => {

        let config = { 'headers': { 'Content-Type': 'application/x-www-form-urlencoded' } };
        let formdata = {
            'grant_type': 'authorization_code',
            'code': code,
            'client_id': COGNITO_DASHBOARD_APP_CLIENT_ID,
            'redirect_uri': `${COGNITO_DASHBOARD_CALLBACK_URL}`
        };
        let data = formurlencoded(formdata);
        //console.log('form data: ', data);
        try {
            let response = await axios.post(COGNITO_TOKEN_ENDPOINT, data, config);
            //console.log('Cognito get tokens res: ', response.data);
            resolve(response.data);
        }
        catch (error) {
            console.log(error);
            resolve(null);
        }

    });
}

function checkAdminStatus(token) {
    return new Promise(async (resolve, reject) => {
        let adminStatus = false;

        //console.log("inside check admin");

        if (token['cognito:groups'] != undefined) {

            token['cognito:groups'].forEach(group => {
                if (group === 'cc_employee_admin') {
                    adminStatus = true;
                }
            });
        }
        resolve(adminStatus);
    });
}

/* Access Level 
    Used to control access to web portal features.
    Level is determined by whether or not a user is in a special group
    or simply a customer.  This is done in Cognito.

    - customer, not assigned to a group
    - cc_employee    - precedence 5
    - cc_employee_cs - precedence 4
    - cc_employee_admin - 3
*/
const cc_employee_admin = 2;
const cc_employee_cs = 3;
const cc_employee_buis = 4;
const cc_employee = 5;
const cc_customer = 99;
function getAccessLevel(token) {
    return new Promise(async (resolve, reject) => {
        let accessLevel = cc_customer;

        //    console.log("inside getAccessLevel ");

        if (token['cognito:groups'] != undefined) {

            token['cognito:groups'].forEach(group => {
                //        console.log(group);
                if (group === 'cc_employee') {
                    if (cc_employee < accessLevel) {
                        accessLevel = cc_employee;
                        //               console.log('set access to employee');
                    }
                }
                if (group === 'cc_employee_buis') {
                    if (cc_employee_buis < accessLevel)
                        accessLevel = cc_employee_buis;
                }
                if (group === 'cc_employee_cs') {
                    if (cc_employee_cs < accessLevel)
                        accessLevel = cc_employee_cs;
                }
                if (group === 'cc_employee_admin') {
                    if (cc_employee_admin < accessLevel) {
                        accessLevel = cc_employee_admin;
                        //                console.log('set access to admin: ', accessLevel);
                    }
                }

            });
        }
        //   console.log('returning accessLevel of: ',accessLevel);
        resolve(accessLevel);
    });
}

function refreshTokens(refresh_token) {
    return new Promise(async (resolve, reject) => {
        let config = {
            'headers': {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        };
        let formdata = {
            'grant_type': 'refresh_token',
            'client_id': COGNITO_DASHBOARD_APP_CLIENT_ID,
            'refresh_token': refresh_token
        };
        let data = formurlencoded(formdata);
        //console.log('form data: ', data);
        try {
            let response = await axios.post(COGNITO_TOKEN_ENDPOINT, data, config);
            //console.log('Cognito get tokens from refresh token: ', response.data);
            resolve(response.data);
        }
        catch (error) {
            console.log(error);
            reject(error);
        }
    });
}

async function validateToken(token) {
    let decodedTokenHeader = jwt_decode(token, { header: true });
    //let decodedToken = jwt_decode(token);
    //console.log(decodedTokenHeader);
    //console.log(decodedToken);

    let jwkIndex = COGNITO_JWK.keys.findIndex(key => {
        if (key.kid == decodedTokenHeader.kid) {
            return key;
        }
    });
    //console.log('jwkIndex: ', COGNITO_JWK.keys[jwkIndex]);
    let pem = jwkToPem(COGNITO_JWK.keys[jwkIndex]);

    let validToken = jwt.verify(token, pem, { algorithms: ['RS256'] }, (err, decodedToken) => {
        if (err) {
            console.log(err);
            return null;
        }
        else {
            //console.log('the token: ', decodedToken);
            return decodedToken;
        }
    });

    //console.log('valid token ', validToken);

    if (validToken != null && (validToken.aud == COGNITO_DASHBOARD_APP_CLIENT_ID) && (validToken.iss == COGNITO_JWT_ISS)) {
        //    console.log('token is valid');
        return validToken;
    }
    else
        return null;
};


async function getCookieTokens(req) {
    let tokens = {};
    if (req.cookies != undefined && req.cookies.id_token != undefined) {
        //console.log('cookies: ', JSON.stringify(req.cookies));
        tokens.id_token = req.cookies.id_token;
    }
    if (req.cookies != undefined && req.cookies.access_token != undefined) {
        tokens.access_token = req.cookies.access_token;
    }
    if (req.cookies != undefined && req.cookies.refresh_token != undefined) {
        tokens.refresh_token = req.cookies.refresh_token;
    }

    if (_.isEmpty(tokens))
        return {};
    else
        return tokens;
}

function setCookies(res, tokens, id_token) {
    return new Promise((resolve, reject) => {
        // console.log('set cookie - httpOnly ');

        if (tokens.id_token != undefined) {
            //console.log('set id_token cookie');
            res.cookie('id_token', tokens.id_token, {
                exp: new Date(id_token.exp),
                httpOnly: true,
                secure: true,
                sameSite: 'Strict'
            });
        }

        if (tokens.refresh_token != undefined) {
            //console.log('set refresh_token');
            res.cookie('refresh_token', tokens.refresh_token, {
                maxAge: (3600000 * 24 * 30),
                httpOnly: true,
                secure: true,
                sameSite: 'Strict'
            });
        }
        //    console.log('return from setting cookies');
        resolve(res);
    });
}

async function getUserSessions(tokens, user_uuid) {
    try {
        let config = {};
        config.headers = {
            'x-api-key': 'nwteRfnwG87Pj6uLz6nq58N0BW8F4KIh8Zi7cUiA',
            'Authorization': tokens.id_token
        };
        let response = await axios.get(`https://api.campchef.site/device-v3/sessions?uuid=${user_uuid}`, config);

        //console.log("user sessions: ", response.data);
        return response.data;
    }
    catch (error) {
        console.log(error);
    }
}

async function deleteUserSession(tokens, user_uuid, sessionId) {
    try {
        let config = {};
        config.headers = {
            'x-api-key': 'nwteRfnwG87Pj6uLz6nq58N0BW8F4KIh8Zi7cUiA',
            'Authorization': tokens.id_token
        };
        let response = await axios.delete(`https://api.campchef.site/device-v3/session/delete?uuid=${user_uuid}&sessionId=${sessionId}`, config);

        //console.log("user sessions: ", response.data);
        return response.data;
    }
    catch (error) {
        console.log(error);
    }

}
async function restoreUserSession(tokens, user_uuid, sessionId) {
    try {
        let config = {};
        config.headers = {
            'x-api-key': 'nwteRfnwG87Pj6uLz6nq58N0BW8F4KIh8Zi7cUiA',
            'Authorization': tokens.id_token
        };
        let data = {
            "uuid": user_uuid,
            "sessionId": sessionId
        };
        let response = await axios.patch(`https://api.campchef.site/device-v3/session/restore`, data, config);

        //console.log("user sessions: ", response.data);
        return response.data;
    }
    catch (error) {
        console.log(error);
    }

}

async function getSessionData(tokens, sessionId, mac) {
    try {
        let config = {};
        config.headers = {
            'x-api-key': admin_api_token,
            'Authorization': tokens.id_token
        };
        let response = await axios.get(`https://api.campchef.site/device-v3/session?sessionId=${sessionId}&mac=${mac}`, config);

        //  console.log("session data: ", response.data);
        return response.data;
    }
    catch (error) {
        console.log(error);
    }
}

async function getLiveSession(tokens, mac) {
    try {
        let config = {};
        config.headers = {
            'x-api-key': admin_api_token,
            'Authorization': tokens.id_token
        };
        let response = await axios.get(`https://api.campchef.site/device-v3/session/current?&mac=${mac}`, config);

        //console.log("session data: ", response.data);
        return response.data;
    }
    catch (error) {
        console.log(error);
    }
}


function sendNewSessionRequest(mac, idToken) {
    return new Promise(async (resolve, reject) => {

        let config = {
            'headers': {
                'Content-Type': 'application/x-www-form-urlencoded',
                'x-api-key': admin_api_token,
                'Authorization': idToken
            }
        };
        let formdata = {
            'mac': mac
        };
        try {
            let response = await axios.post('https://api.campchef.site/device-v3/session/new', formdata, config);
            console.log('Send Firmware Update Response: ', response.data);
            resolve(response.data);
        }
        catch (error) {
            console.log(error);
            resolve(error);
        }
    });
}

function sendEndSessionRequest(mac, idToken) {
    return new Promise(async (resolve, reject) => {

        let config = {
            'headers': {
                'Content-Type': 'application/x-www-form-urlencoded',
                'x-api-key': admin_api_token,
                'Authorization': idToken
            }
        };
        let formdata = {
            'mac': mac
        };
        try {
            let response = await axios.post('https://api.campchef.site/device-v3/session/current/end', formdata, config);
            //    console.log('Send Firmware Update Response: ', response.data);
            resolve(response.data);
        }
        catch (error) {
            console.log(error);
            resolve(error);
        }
    });
}


function authorize(req, res) {
    return new Promise(async (resolve, reject) => {

        let resp = {};
        resp.login = true;
        resp.validIdToken = null;

        resp.tokens = await getCookieTokens(req);
        if (!_.isEmpty(resp.tokens)) {
            if (resp.tokens.id_token != undefined) {
                resp.validIdToken = await validateToken(resp.tokens.id_token);
            }

            if (resp.validIdToken == null && (resp.tokens.refresh_token != undefined)) {
                resp.tokens = await refreshTokens(resp.tokens.refresh_token);
                resp.validIdToken = await validateToken(resp.tokens.id_token);
                await setCookies(res, resp.tokens, resp.validIdToken);
            }
        }

        if (_.isEmpty(req.query) && (req.query.code == undefined) && (resp.validIdToken == null || resp.validIdToken == false)) {
            //console.log('got to login ', DASHBOARD_COGNITO_LOGIN_URL);
            // res.render('pages/login', { cognito_login_url: DASHBOARD_COGNITO_LOGIN_URL });
            resp.login = true;
        }
        else {
            if (req.query.code != undefined && (resp.validIdToken == null || resp.validIdToken == false)) {
                //get token
                //console.log('call get tokens', validIdToken);
                resp.tokens = await getCognitoToken(req.query.code);
                if (resp.tokens != null) {
                    //console.log('validate id_token: ', tokens.id_token);
                    resp.validIdToken = await validateToken(resp.tokens.id_token); //valid Id token is decoded.
                    await setCookies(res, resp.tokens, resp.validIdToken);
                    resp.login = false;
                }
            }
        }


        resolve(resp);

    });
}




app.use(favicon(path.join(__dirname, 'public/favicon', 'favicon.ico')));
//app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));


/*******************************************************************************************************************************************/
app.get('/', async (req, res) => {
    res.render('pages/index_test.html', {});
});


app.get('/v3', async (req, res) => {
//app.get('/', async (req, res) => {    

    let validIdToken = null;
    let tokens = {};

    let authResp = await authorize(req, res);
    tokens = authResp.tokens;
    validIdToken = authResp.validIdToken;


    if (validIdToken) {
        //let admin = await checkAdminStatus(validIdToken);
        let accessLevel = await getAccessLevel(validIdToken);
        //    console.log('access level: ', accessLevel);

        let email = '';
        if (!_.isEmpty(req.query) && (req.query.email != undefined) && (req.query.email != null) && (accessLevel == cc_employee_cs || accessLevel == cc_employee_admin)) {
            email = req.query.email;
        }
        else {
            if (accessLevel != cc_employee_cs) {
                email = validIdToken.email;
            }
        }

        let onlineCount = null;
        if (accessLevel <= cc_employee) {
            onlineCount = await getOnlineDeviceCount(tokens.id_token);
        }

        //    console.log('email: ', email);
        //console.log('id token: ', tokens.id_token);

        if (email != '') {
            let userInfoDevices = await getUserDevicesByEmail(email, tokens.id_token);
            //        console.log('userInfoDevices: ', JSON.stringify(userInfoDevices));
            if (userInfoDevices == null) {
                //            console.log('user info is null');
                userInfoDevices.userDevices[0] = null;
            }
            //        console.log(validIdToken);

            res.render('pages/index', {
                email: email,
                online: onlineCount,
                userUUID: userInfoDevices.userDevices[0].user_uuid,
                deviceId: "",
                devices: userInfoDevices.userDevices,
                userToken: validIdToken
            });
        }
        else {


            let versions = await getAllVersions(tokens.id_token);

            let models = Object.keys(versions);

            //    console.log(JSON.stringify( models));

            let modelVerInfo = [];
            models.forEach(model => {
                let modelInfo = {};
                if (versions[model].latest != null) {

                    modelInfo[model.toUpperCase()] = versions[model].latest;
                    modelVerInfo.push(modelInfo);
                }
            });

            //   console.log(modelVerInfo);

            res.render('pages/index_cs', {
                email: email,
                online: onlineCount,
                userUUID: "",
                deviceId: "",
                versions: modelVerInfo,
                userToken: validIdToken
            });

        }
    }
    else {
        console.log('token is null');
        let devices = null;
        let email = "";
        res.render('pages/login', { cognito_login_url: DASHBOARD_COGNITO_LOGIN_URL });
    }
    //    }

});


app.get('/v3/active', async (req, res) => {

    let validIdToken = null;
    let tokens = {};

    let devices = null;
    let deviceId = "";
    let email = "";
    let userUUID = "";

    // tokens = await getCookieTokens(req);
    // if (!_.isEmpty(tokens)) {
    //     if (tokens.id_token != undefined) {
    //         validIdToken = await validateToken(tokens.id_token);
    //     }

    //     if (validIdToken == null && (tokens.refresh_token != undefined)) {
    //         tokens = await refreshTokens(tokens.refresh_token);
    //         validIdToken = await validateToken(tokens.id_token);
    //         await setCookies(res, tokens, validIdToken);
    //     }
    // }

    // if (_.isEmpty(req.query) && (req.query.code == undefined) && (validIdToken == null)) {
    //     //console.log('got to login ', DASHBOARD_COGNITO_LOGIN_URL);
    //     res.render('pages/login', { cognito_login_url: DASHBOARD_COGNITO_LOGIN_URL });
    // }
    // else {

    //     if (req.query.code != undefined && validIdToken == null) {
    //         //get token
    //         //console.log('call get tokens');
    //         tokens = await getCognitoToken(req.query.code);
    //         validIdToken = await validateToken(tokens.id_token); //valid Id token is decoded.
    //     }

    let authResp = await authorize(req, res);
    tokens = authResp.tokens;
    validIdToken = authResp.validIdToken;

    if (validIdToken) {
        let accessLevel = await getAccessLevel(validIdToken);
        //    console.log('access level: ', accessLevel);

        if (validIdToken && accessLevel != cc_customer) {
            await setCookies(res, tokens, validIdToken);

            let numActive = await getOnlineDeviceCount(tokens.id_token);
            let devices = await getActiveDevices(tokens.id_token);

            //    console.log("active devices: ", devices);


            res.render('pages/active', {
                email: "",
                online: numActive,
                userUUID: "",
                deviceId: "",
                devices: devices,
                userToken: validIdToken
            });


        } else {
            console.log('token is null');
            let devices = null;
            let email = "";
            res.render('pages/index', {
                email: email,
                online: null,
                userUUID, userUUID,
                deviceId: "",
                devices: devices,
                userToken: validIdToken
            });
        }
    }
    else {
        console.log('token is null');
        let devices = null;
        let email = "";
        res.render('pages/login', { cognito_login_url: DASHBOARD_COGNITO_LOGIN_URL });
    }
});



app.get('/v3/status', async (req, res) => {

    let validIdToken = null;
    let tokens = {};

    // tokens = await getCookieTokens(req);
    // if (!_.isEmpty(tokens)) {
    //     if (tokens.id_token != undefined) {
    //         validIdToken = await validateToken(tokens.id_token);
    //     }
    //     if (validIdToken == null && (tokens.refresh_token != undefined)) {
    //         tokens = await refreshTokens(tokens.refresh_token);
    //         validIdToken = await validateToken(tokens.id_token);
    //         await setCookies(res, tokens, validIdToken);
    //     }
    // }

    // if (_.isEmpty(req.query) && (req.query.code == undefined) && (validIdToken == null || validIdToken == false)) {
    //     res.render('pages/login', { cognito_login_url: DASHBOARD_COGNITO_LOGIN_URL });
    // }
    // else {
    //     if (req.query.code != undefined && (validIdToken == null || validIdToken == false)) {
    //         //get token
    //         //console.log('call get tokens', validIdToken);
    //         tokens = await getCognitoToken(req.query.code);
    //         if (tokens != null) {
    //             //console.log('validate id_token: ', tokens.id_token);
    //             validIdToken = await validateToken(tokens.id_token); //valid Id token is decoded.
    //             await setCookies(res, tokens, validIdToken);
    //         }
    //     }


    let authResp = await authorize(req, res);
    tokens = authResp.tokens;
    validIdToken = authResp.validIdToken;

    if (validIdToken) {
        //let admin = await checkAdminStatus(validIdToken);
        let accessLevel = await getAccessLevel(validIdToken);
        console.log('access level: ', accessLevel);

        if (accessLevel == cc_employee_admin) {

            let info = {};
            info.redis = await getRedisInfo(tokens.id_token);

            info.redisDisplay = {};

            info.redis.info.forEach(element => {
                let strSplit = element.split(':');

                let temp = null;
                let temp1 = null;
                switch (strSplit[0]) {

                    case 'used_memory':
                        info.redisDisplay.used_memory = strSplit[1];
                        break;

                    case 'used_memory_human':
                        info.redisDisplay.used_memory_humman = strSplit[1];
                        break;

                    case 'used_memory_peak':
                        info.redisDisplay.used_memory_peak = strSplit[1];
                        break;

                    case 'used_memory_peak_human':
                        info.redisDisplay.used_memory_peak_human = strSplit[1];
                        break;

                    case 'used_memory_rss':
                        info.redisDisplay.used_memory_rss = strSplit[1];
                        break;

                    case 'used_memory_rss_human':
                        info.redisDisplay.used_memory_rss_human = strSplit[1];
                        break;


                    case 'mem_fragmentation_ratio':
                        info.redisDisplay.mem_framentation_ratio = strSplit[1];
                        break;

                    case 'connected_slaves':
                        info.redisDisplay.connected_slaves = strSplit[1];
                        break;

                    case 'slave0':
                        temp = strSplit[1].split(',');
                        info.redisDisplay.replica0 = {};
                        temp.forEach(element => {
                            temp1 = element.split('=');
                            switch (temp1[0]) {
                                case 'ip':
                                    info.redisDisplay.replica0.ip = temp1[1];
                                    break;
                                case 'port':
                                    info.redisDisplay.replica0.port = temp1[1];
                                    break;
                                case 'state':
                                    info.redisDisplay.replica0.state = temp1[1];
                                    break;
                                default:
                                    break;
                            }
                        });
                        break;

                    case 'slave1':
                        temp = strSplit[1].split(',');
                        info.redisDisplay.replica1 = {};
                        temp.forEach(element => {
                            temp1 = element.split('=');
                            switch (temp1[0]) {
                                case 'ip':
                                    info.redisDisplay.replica1.ip = temp1[1];
                                    break;
                                case 'port':
                                    info.redisDisplay.replica1.port = temp1[1];
                                    break;
                                case 'state':
                                    info.redisDisplay.replica1.state = temp1[1];
                                    break;
                                default:
                                    break;
                            }
                        });
                        break;

                    case 'keyspace_hits':
                        info.redisDisplay.keyspace_hits = strSplit[1];
                        break;

                    case 'keyspace_misses':
                        info.redisDisplay.keyspace_misses = strSplit[1];
                        break;

                    case 'connected_clients':
                        info.redisDisplay.connected_clients = strSplit[1];
                        break;

                    case 'blocked_clients':
                        info.redisDisplay.blocked_clients = strSplit[1];

                    default:
                        break;

                }


            });

            res.render('pages/status', {
                email: "",
                online: null,
                userUUID: "",
                deviceId: "",
                info: info,
                userToken: validIdToken
            });
        }
        else {
            //res.render('pages/not_auth');
        }

    }
    else {
        console.log('token is null');
        let devices = null;
        let email = "";
        res.render('pages/login', { cognito_login_url: DASHBOARD_COGNITO_LOGIN_URL });
    }
    //   }
});



app.get('/v3/uploadFirmware', async (req, res) => {

    let validIdToken = null;
    let tokens = {};

    // tokens = await getCookieTokens(req);
    // if (!_.isEmpty(tokens)) {
    //     if (tokens.id_token != undefined) {
    //         validIdToken = await validateToken(tokens.id_token);
    //     }
    //     if (validIdToken == null && (tokens.refresh_token != undefined)) {
    //         tokens = await refreshTokens(tokens.refresh_token);
    //         validIdToken = await validateToken(tokens.id_token);
    //         await setCookies(res, tokens, validIdToken);
    //     }
    // }

    // if (_.isEmpty(req.query) && (req.query.code == undefined) && (validIdToken == null || validIdToken == false)) {
    //     res.render('pages/login', { cognito_login_url: DASHBOARD_COGNITO_LOGIN_URL });
    // }
    // else {
    //     if (req.query.code != undefined && (validIdToken == null || validIdToken == false)) {
    //         //get token
    //         //console.log('call get tokens', validIdToken);
    //         tokens = await getCognitoToken(req.query.code);
    //         if (tokens != null) {
    //             //console.log('validate id_token: ', tokens.id_token);
    //             validIdToken = await validateToken(tokens.id_token); //valid Id token is decoded.
    //             await setCookies(res, tokens, validIdToken);
    //         }
    //     }


    let authResp = await authorize(req, res);
    tokens = authResp.tokens;
    validIdToken = authResp.validIdToken;
    if (validIdToken) {
        //let admin = await checkAdminStatus(validIdToken);
        let accessLevel = await getAccessLevel(validIdToken);

        let devFirmwareList = await getDevFirmwareList(tokens.id_token);


        if (accessLevel == cc_employee_admin) {
            res.render('pages/uploadFirmware', {
                email: "",
                online: null,
                userUUID: "",
                deviceId: "",
                userToken: validIdToken,
                firmwareList: devFirmwareList,
                uploadStatus: ""
            });
        }
        else {
            //res.render('pages/not_auth');
            res.render('pages/index');
        }

    }
    else {
        console.log('token is null');
        let devices = null;
        let email = "";
        res.render('pages/login', { cognito_login_url: DASHBOARD_COGNITO_LOGIN_URL });
    }
    //    }
});


app.post('/v3/firmware', upload.single('filename'), async (req, res) => {

    let fileInfoObj = req.file;
    let validIdToken = null;
    let tokens = {};

    // tokens = await getCookieTokens(req);
    // if (!_.isEmpty(tokens)) {
    //     if (tokens.id_token != undefined) {
    //         validIdToken = await validateToken(tokens.id_token);
    //     }
    //     if (validIdToken == null && (tokens.refresh_token != undefined)) {
    //         tokens = await refreshTokens(tokens.refresh_token);
    //         validIdToken = await validateToken(tokens.id_token);
    //         await setCookies(res, tokens, validIdToken);
    //     }
    // }

    // if (_.isEmpty(req.query) && (req.query.code == undefined) && (validIdToken == null || validIdToken == false)) {
    //     res.render('pages/login', { cognito_login_url: DASHBOARD_COGNITO_LOGIN_URL });
    // }
    // else {
    //     if (req.query.code != undefined && (validIdToken == null || validIdToken == false)) {
    //         //get token
    //         //console.log('call get tokens', validIdToken);
    //         tokens = await getCognitoToken(req.query.code);
    //         if (tokens != null) {
    //             //console.log('validate id_token: ', tokens.id_token);
    //             validIdToken = await validateToken(tokens.id_token); //valid Id token is decoded.
    //             await setCookies(res, tokens, validIdToken);
    //         }
    //     }

    let authResp = await authorize(req, res);
    tokens = authResp.tokens;
    validIdToken = authResp.validIdToken;

    if (validIdToken) {
        //let admin = await checkAdminStatus(validIdToken);
        let accessLevel = await getAccessLevel(validIdToken);

        if (accessLevel == cc_employee_admin) {

            fileInfoObj.md5 = md5(fileInfoObj.buffer);
            let uploadStatus = await uploadFirmware(fileInfoObj.originalname, fileInfoObj.buffer, fileInfoObj.md5, tokens.id_token);

            res.send(uploadStatus);
        }
        else {
            res.render('pages/index');
        }

    }
    else {
        console.log('token is null');
        let devices = null;
        let email = "";
        res.render('pages/login', { cognito_login_url: DASHBOARD_COGNITO_LOGIN_URL });
    }
    //    }

    if (fileInfoObj) {
        fileInfoObj = null;
    }

});


app.get('/v3/update', async (req, res) => {

    let validIdToken = null;
    let tokens = {};

    // tokens = await getCookieTokens(req);
    // if (!_.isEmpty(tokens)) {
    //     if (tokens.id_token != undefined) {
    //         validIdToken = await validateToken(tokens.id_token);
    //     }
    //     if (validIdToken == null && (tokens.refresh_token != undefined)) {
    //         tokens = await refreshTokens(tokens.refresh_token);
    //         validIdToken = await validateToken(tokens.id_token);
    //         await setCookies(res, tokens, validIdToken);
    //     }
    // }

    // if (_.isEmpty(req.query) && (req.query.code == undefined) && (validIdToken == null || validIdToken == false)) {
    //     res.render('pages/login', { cognito_login_url: DASHBOARD_COGNITO_LOGIN_URL });
    // }
    // else {
    //     if (req.query.code != undefined && (validIdToken == null || validIdToken == false)) {
    //         //get token
    //         //console.log('call get tokens', validIdToken);
    //         tokens = await getCognitoToken(req.query.code);
    //         if (tokens != null) {
    //             //console.log('validate id_token: ', tokens.id_token);
    //             validIdToken = await validateToken(tokens.id_token); //valid Id token is decoded.
    //             await setCookies(res, tokens, validIdToken);
    //         }
    //     }

    let authResp = await authorize(req, res);
    tokens = authResp.tokens;
    validIdToken = authResp.validIdToken;

    if (validIdToken) {
        //let admin = await checkAdminStatus(validIdToken);
        let accessLevel = await getAccessLevel(validIdToken);
        let mac = req.query.mac;
        // console.log('mac: ', mac);

        let deviceInfo = await getDeviceInfo(mac, tokens.id_token);
        deviceInfo.mac = mac;
        //console.log('device info: ', JSON.stringify(deviceInfo));
        //if (admin && deviceInfo != undefined && deviceInfo != null) {
        //   console.log("access level = ", accessLevel);   
        if ((accessLevel == cc_employee_cs || accessLevel == cc_employee_admin) && deviceInfo != undefined && deviceInfo != null) {

            if (deviceInfo.shadow.state.desired.characteristic.firmware != undefined && deviceInfo.shadow.state.desired.characteristic.firmware.stm32 != undefined) {
                let mcuFirmware = deviceInfo.shadow.state.desired.characteristic.firmware.stm32;
                if (mcuFirmware != '') {
                    var deviceType = mcuFirmware.slice(0, 4).toLowerCase();
                    var currentMCUversion = mcuFirmware.slice(6, 20).toLowerCase();
                }
                if (deviceInfo.shadow.state.desired.characteristic.firmware != undefined && deviceInfo.shadow.state.desired.characteristic.firmware.esp32 != undefined) {
                    var wifiFirmware = deviceInfo.shadow.state.desired.characteristic.firmware.esp32;
                }
            }

            let updates = {};
            updates.espUpdates = await getESPUpdates(wifiFirmware, tokens.id_token);
            updates.stmUpdates = await getSTMUpdates(currentMCUversion, deviceType, tokens.id_token);
            updates.stmUpdates.dev = await await getDevFirmwareList(tokens.id_token, deviceType);

            console.log('stm dev versions: ', updates.stmUpdates.dev);

            console.log('updates: ', JSON.stringify(updates));
            //    console.log('stm updates: ', JSON.stringify(updates.stmUpdates));
            deviceInfo.updates = { ...updates };

            res.render('pages/update', {
                device: deviceInfo,
                email: "",
                online: null,
                userUUID: "",
                deviceId: "",
                userToken: validIdToken
            });
        }
        else {
            //res.render('pages/not_auth');
        }

    }
    else {
        console.log('token is null');
        let devices = null;
        let email = "";
        res.render('pages/login', { cognito_login_url: DASHBOARD_COGNITO_LOGIN_URL });
    }
    //    }

});


app.post('/v3/sendupdate', async (req, res) => {

    let validIdToken = null;
    let tokens = {};

    // tokens = await getCookieTokens(req);
    // if (!_.isEmpty(tokens)) {
    //     if (tokens.id_token != undefined) {
    //         validIdToken = await validateToken(tokens.id_token);
    //     }
    //     if (validIdToken == null && (tokens.refresh_token != undefined)) {
    //         tokens = await refreshTokens(tokens.refresh_token);
    //         validIdToken = await validateToken(tokens.id_token);
    //         await setCookies(res, tokens, validIdToken);
    //     }
    // }

    // if (_.isEmpty(req.query) && (req.query.code == undefined) && (validIdToken == null || validIdToken == false)) {
    //     res.render('pages/login', { cognito_login_url: DASHBOARD_COGNITO_LOGIN_URL });
    // }
    // else {
    //     if (req.query.code != undefined && (validIdToken == null || validIdToken == false)) {
    //         //get token
    //         //console.log('call get tokens', validIdToken);
    //         tokens = await getCognitoToken(req.query.code);
    //         if (tokens != null) {
    //             //console.log('validate id_token: ', tokens.id_token);
    //             validIdToken = await validateToken(tokens.id_token); //valid Id token is decoded.
    //             await setCookies(res, tokens, validIdToken);
    //         }
    //     }

    let authResp = await authorize(req, res);
    tokens = authResp.tokens;
    validIdToken = authResp.validIdToken;

    if (validIdToken) {
        let accessLevel = await getAccessLevel(validIdToken);
        if ((accessLevel == cc_employee_admin || accessLevel == cc_employee_cs) && !_.isEmpty(req.body)) {


            //if (!_.isEmpty(req.body) && req.body.mac != undefined && admin) {

            //    console.log('req.body: ', req.body);

            let mac = req.body.mac;
            let part = req.body.part;
            let updateVersion = JSON.parse(req.body.version);

            //     console.log('mac: ', mac);
            //    console.log('version ', updateVersion)
            let sendStatus = await sendUpdateInfo(mac, part, updateVersion, tokens.id_token);
            //    console.log('response to send update ', sendStatus);

            res.send("Update request sent!");
        }
        else {
            res.send('pages/not_auth');
        }

    }
    else {
        //    console.log('token is null');
        let devices = null;
        let email = "";
        res.render('pages/login', { cognito_login_url: DASHBOARD_COGNITO_LOGIN_URL });
    }
    //    }

});

app.get('/v3/view', async (req, res) => {

    let validIdToken = null;
    let tokens = {};

    // tokens = await getCookieTokens(req);
    // if (!_.isEmpty(tokens)) {
    //     if (tokens.id_token != undefined) {
    //         validIdToken = await validateToken(tokens.id_token);
    //     }
    //     if (validIdToken == null && (tokens.refresh_token != undefined)) {
    //         tokens = await refreshTokens(tokens.refresh_token);
    //         validIdToken = await validateToken(tokens.id_token);
    //         await setCookies(res, tokens, validIdToken);
    //     }
    // }

    // if (_.isEmpty(req.query) && (req.query.code == undefined) && (validIdToken == null || validIdToken == false)) {
    //     res.render('pages/login', { cognito_login_url: DASHBOARD_COGNITO_LOGIN_URL });
    // }
    // else {
    //     if (req.query.code != undefined && (validIdToken == null || validIdToken == false)) {
    //         //get token
    //         //console.log('call get tokens', validIdToken);
    //         tokens = await getCognitoToken(req.query.code);
    //         if (tokens != null) {
    //             //console.log('validate id_token: ', tokens.id_token);
    //             validIdToken = await validateToken(tokens.id_token); //valid Id token is decoded.
    //             await setCookies(res, tokens, validIdToken);
    //         }
    //     }

    let authResp = await authorize(req, res);
    tokens = authResp.tokens;
    validIdToken = authResp.validIdToken;

    if (validIdToken) {
        //let admin = await checkAdminStatus(validIdToken);
        let accessLevel = await getAccessLevel(validIdToken);
        let mac = req.query.mac;
        //    console.log('access level: ', accessLevel);

        let deviceInfo = await getDeviceInfo(mac, tokens.id_token);
        deviceInfo.mac = mac;
        //    console.log('View -- device info: ', JSON.stringify(deviceInfo));
        if ((accessLevel == cc_employee_cs || accessLevel == cc_employee_admin) && deviceInfo != undefined && deviceInfo != null) {

            let email = validIdToken.email;
            if (!_.isEmpty(req.query) && req.query.email != undefined && req.query.email != null) {
                email = req.query.email;
                //            console.log("admin - get devices for: ", email);
            }

            let userUUID = null;
            if (!_.isEmpty(req.query) && req.query.userUUID != undefined && req.query.userUUID != null) {
                userUUID = req.query.userUUID;
            }

            res.render('pages/view', {
                device: deviceInfo,
                email: email,
                online: null,
                userUUID: userUUID,
                deviceId: "",
                userToken: validIdToken
            });
        }
        else {
            //res.render('pages/not_auth');
        }

    }
    else {
        //    console.log('token is null');
        let devices = null;
        let email = "";
        res.render('pages/login', { cognito_login_url: DASHBOARD_COGNITO_LOGIN_URL });
    }
    //   }

});

app.post('/v3/control', async (req, res) => {
    let validIdToken = null;
    let tokens = {};
    let responseStr = '';

    // tokens = await getCookieTokens(req);
    // if (!_.isEmpty(tokens)) {
    //     if (tokens.id_token != undefined) {
    //         validIdToken = await validateToken(tokens.id_token);
    //     }
    //     if (validIdToken == null && (tokens.refresh_token != undefined)) {
    //         tokens = await refreshTokens(tokens.refresh_token);
    //         validIdToken = await validateToken(tokens.id_token);
    //         await setCookies(res, tokens, validIdToken);
    //     }
    // }

    // if (_.isEmpty(req.query) && (req.query.code == undefined) && (validIdToken == null || validIdToken == false)) {
    //     res.render('pages/login', { cognito_login_url: DASHBOARD_COGNITO_LOGIN_URL });
    // }
    // else {
    //     if (req.query.code != undefined && (validIdToken == null || validIdToken == false)) {
    //         //get token
    //         //console.log('call get tokens', validIdToken);
    //         tokens = await getCognitoToken(req.query.code);
    //         if (tokens != null) {
    //             //console.log('validate id_token: ', tokens.id_token);
    //             validIdToken = await validateToken(tokens.id_token); //valid Id token is decoded.
    //             await setCookies(res, tokens, validIdToken);
    //         }
    //     }

    let authResp = await authorize(req, res);
    tokens = authResp.tokens;
    validIdToken = authResp.validIdToken;

    if (validIdToken) {
        let admin = await checkAdminStatus(validIdToken);
        if (!_.isEmpty(req.body) && req.body.mac != undefined && admin) {

            let controlObj = {};
            controlObj.mac = req.body.mac;
            if (req.body.temp != undefined) {
                controlObj.setTemp = req.body.temp;
            }
            if (req.body.smoke != undefined) {
                controlObj.setSmoke = req.body.smoke;
            }
            if (req.body.fan != undefined) {
                controlObj.setFan = req.body.fan;
            }
            if (req.body.mode != undefined && req.body.mode == 4) {
                controlObj.mode = req.body.mode;
            }
            //    console.log('control obj: ', controlObj);

            //send the control object to backend
            let controlResp = await sendControlData(controlObj, tokens.id_token);
            responseStr = controlResp;
        }
        else if (!admin) {
            responseStr = 'Not Authorized to change settings';
        }
        else {
            responseStr = 'Missing setting value';
        }
    }
    else {
        responseStr = 'Not Authorized to change settings';
    }

    res.send(responseStr);
    //    }
});


app.get('/v3/view_refresh', async (req, res) => {

    let validIdToken = null;
    let tokens = {};

    // tokens = await getCookieTokens(req);
    // if (!_.isEmpty(tokens)) {
    //     if (tokens.id_token != undefined) {
    //         validIdToken = await validateToken(tokens.id_token);
    //     }
    //     if (validIdToken == null && (tokens.refresh_token != undefined)) {
    //         tokens = await refreshTokens(tokens.refresh_token);
    //         validIdToken = await validateToken(tokens.id_token);
    //         await setCookies(res, tokens, validIdToken);
    //     }
    // }

    // if (_.isEmpty(req.query) && (req.query.code == undefined) && (validIdToken == null || validIdToken == false)) {
    //     res.render('pages/login', { cognito_login_url: DASHBOARD_COGNITO_LOGIN_URL });
    // }
    // else {
    //     if (req.query.code != undefined && (validIdToken == null || validIdToken == false)) {
    //         //get token
    //         //console.log('call get tokens', validIdToken);
    //         tokens = await getCognitoToken(req.query.code);
    //         if (tokens != null) {
    //             //console.log('validate id_token: ', tokens.id_token);
    //             validIdToken = await validateToken(tokens.id_token); //valid Id token is decoded.
    //             await setCookies(res, tokens, validIdToken);
    //         }
    //     }

    let authResp = await authorize(req, res);
    tokens = authResp.tokens;
    validIdToken = authResp.validIdToken;

    if (validIdToken) {
        let admin = await checkAdminStatus(validIdToken);
        let mac = req.query.mac;
        //    console.log('mac: ', mac);

        let deviceInfo = await getDeviceInfo(mac, tokens.id_token);
        deviceInfo.mac = mac;
        //console.log('device info: ', JSON.stringify(deviceInfo));
        if (admin && deviceInfo != undefined && deviceInfo != null) {
            delete deviceInfo.shadow["metadata"];

            // let email = validIdToken.email;
            // if (!_.isEmpty(req.query) && req.query.email != undefined && req.query.email != null && admin) {
            //     email = req.query.email;
            //     console.log("admin - get devices for: ", email);
            // }

            // let userUUID = null;
            // if (!_.isEmpty(req.query) && req.query.userUUID != undefined && req.query.userUUID != null) {
            //     userUUID = req.query.userUUID;
            // }


            // res.render('pages/view', {
            //     device: deviceInfo,
            //     email: email,
            //     userUUID: userUUID,
            //     deviceId: "",
            //     userToken: validIdToken
            // });

            //    console.log(deviceInfo);
            res.send(deviceInfo);

        }
        else {
            //res.render('pages/not_auth');
            res.render({});
        }

    }
    else {
        console.log('token is null');
        let devices = null;
        let email = "";
        res.render('pages/login', { cognito_login_url: DASHBOARD_COGNITO_LOGIN_URL });
    }
    //    }

});


app.get('/v3/busi', async (req, res) => {

    let validIdToken = null;
    let tokens = {};
    // tokens = await getCookieTokens(req);
    // if (!_.isEmpty(tokens)) {
    //     if (tokens.id_token != undefined) {
    //         validIdToken = await validateToken(tokens.id_token);
    //     }

    //     if (validIdToken == null && (tokens.refresh_token != undefined)) {
    //         tokens = await refreshTokens(tokens.refresh_token);
    //         validIdToken = await validateToken(tokens.id_token);
    //         await setCookies(res, tokens, validIdToken);
    //     }
    // }
    // if (_.isEmpty(req.query) && (req.query.code == undefined) && (validIdToken == null)) {
    //     //console.log('got to login ', DASHBOARD_COGNITO_LOGIN_URL);
    //     res.render('pages/login', { cognito_login_url: DASHBOARD_COGNITO_LOGIN_URL });
    // }
    // else {

    //     if (req.query.code != undefined && validIdToken == null) {
    //         //get token
    //         //console.log('call get tokens');
    //         tokens = await getCognitoToken(req.query.code);
    //         //console.log('validate id_token: ', tokens.id_token);
    //         validIdToken = await validateToken(tokens.id_token); //valid Id token is decoded.
    //         await setCookies(res, tokens, validIdToken);
    //     }


    let authResp = await authorize(req, res);
    tokens = authResp.tokens;
    validIdToken = authResp.validIdToken;

    let devices = null;
    let email = "";
    if (validIdToken) {
        //let admin = await checkAdminStatus(validIdToken);
        let accessLevel = await getAccessLevel(validIdToken);
        //Get device cooked history from DB via API
        let cooked = await getCookedCount(tokens);
        let totalDevicesPromise = getDeviceCount(tokens);
        let totalUsersPromise = getUserCount(tokens);
        let totalGraphUsersPromise = getTotalGraphUsers(tokens);
        let totalDevices = null;
        let totalUsers = null;
        let totalGraphUsers = null;
        await Promise.all([totalDevicesPromise, totalUsersPromise, totalGraphUsersPromise])
            .then((promiseValues) => {
                totalDevices = promiseValues[0];
                totalUsers = promiseValues[1];
                totalGraphUsers = promiseValues[2];
            });

        //Get current day cooked device from Redis via API

        let date = [];
        let dayTotal = [];
        let totalCooked = null;
        cooked.cookStats.forEach(day => {
            let dateParts = day.date.split('_');
            let cookedDate = new Date(`${dateParts[2]}-${dateParts[0]}-${dateParts[1]}`);
            date.push(cookedDate);
            dayTotal.push(day.total_cooked);
            totalCooked += day.total_cooked;
        });
        let stats = {};
        stats.date = date;
        stats.total = dayTotal;
        stats.deviceCount = parseInt(totalDevices);
        stats.userCount = parseInt(totalUsers);


        stats.toDateTotal = totalCooked;


        stats.totalGraphUsers = totalGraphUsers;


        let onlineCount = null;
        if (accessLevel <= cc_employee) {
            onlineCount = await getOnlineDeviceCount(tokens.id_token);
            res.render('pages/businessInfo', {
                email: "",
                userUUID: "",
                online: onlineCount,
                deviceId: "",
                stats: stats,
                userToken: validIdToken
            });
        }
        else {
            res.render('pages/businessInfo', {
                email: "",
                online: onlineCount,
                userUUID: "",
                deviceId: "",
                cookStats: "",
                userToken: validIdToken
            });
        }

    }
    else {
        //    console.log('token is null');
        res.render('pages/login', { cognito_login_url: DASHBOARD_COGNITO_LOGIN_URL });
    }

    //    }
});



app.get('/v3/sessions', async (req, res) => {

    let validIdToken = null;
    let tokens = {};
    // tokens = await getCookieTokens(req);
    // if (!_.isEmpty(tokens)) {
    //     if (tokens.id_token != undefined) {
    //         validIdToken = await validateToken(tokens.id_token);
    //     }

    //     if (validIdToken == null && (tokens.refresh_token != undefined)) {
    //         tokens = await refreshTokens(tokens.refresh_token);
    //         validIdToken = await validateToken(tokens.id_token);
    //         await setCookies(res, tokens, validIdToken);
    //     }
    // }

    // if (_.isEmpty(req.query) && (req.query.code == undefined) && (validIdToken == null)) {
    //     //console.log('got to login ', DASHBOARD_COGNITO_LOGIN_URL);
    //     res.render('pages/login', { cognito_login_url: DASHBOARD_COGNITO_LOGIN_URL });
    // }
    // else {

    //     if (req.query.code != undefined && validIdToken == null) {
    //         //get token
    //         // console.log('call get tokens');
    //         tokens = await getCognitoToken(req.query.code);
    //         // console.log('validate id_token: ', tokens.id_token);
    //         validIdToken = await validateToken(tokens.id_token); //valid Id token is decoded.
    //         await setCookies(res, tokens, validIdToken);
    //     }

    let authResp = await authorize(req, res);
    tokens = authResp.tokens;
    validIdToken = authResp.validIdToken;

    if (validIdToken) {
        //let admin = await checkAdminStatus(validIdToken);
        let accessLevel = await getAccessLevel(validIdToken);
        let email = '';
        let userUUID = '';
        let timeZone_offset_minutes


        if (!_.isEmpty(req.query) && req.query.userUUID != undefined && req.query.userUUID != null) {

            //        console.log('request query: ', req.query);

            if (req.query.histEmail != undefined) {
                email = req.query.histEmail;
            }
            if (req.query.tz_offset != undefined) {
                timeZone_offset_minutes = req.query.tz_offset;
                //console.log('time zone offset: ', timeZone_offset_minutes);
            }

            //if admin get history for requested user uuid, else only allow user uuid for logged in user
            if (accessLevel == cc_employee_admin || accessLevel == cc_employee_cs) {
                userUUID = req.query.userUUID;
            }
            else {
                userUUID = validIdToken.sub;
                email = validIdToken.email;
            }
            if (req.query.deleteSessionId != undefined && req.query.deleteSessionId != null) {
                //                 console.log('delete session: ', req.query.deleteSessionId);
                await deleteUserSession(tokens, userUUID, req.query.deleteSessionId);
            }
            if (req.query.restoreSessionId != undefined && req.query.restoreSessionId != null) {
                //            console.log('restore session: ', req.query.restoreSessionId);
                await restoreUserSession(tokens, userUUID, req.query.restoreSessionId);
            }
        }

        let sessionsData = await getUserSessions(tokens, userUUID);
        let sessionsList = null;
        let sessionsMac = null;
        if (!_.isEmpty(sessionsData) && sessionsData.sessions != undefined) {
            sessionsList = sessionsData.sessions;
            sessionsMac = sessionsData.mac;

            sessionsList.forEach(session => {
                let localStart = new Date(parseInt(session.start_time) - parseInt(timeZone_offset_minutes * 60 * 1000));
                session.localStartDateTime = localStart.toLocaleDateString('us-EN') + ' ' + localStart.toLocaleTimeString('us-EN');
            });

        }
        //console.log('sessions: ', sessionsData);
        res.render('pages/history', {
            email: email,
            online: null,
            userUUID: userUUID,
            deviceId: "",
            sessions: sessionsList,
            mac: sessionsMac,
            userToken: validIdToken
        });
    }
    else {
        //       console.log('token is null');

        res.render('pages/login', { cognito_login_url: DASHBOARD_COGNITO_LOGIN_URL });
    }
    //    }
});


app.post('/v3/start_session', async (req, res) => {

    let validIdToken = null;
    let tokens = {};

    // tokens = await getCookieTokens(req);
    // if (!_.isEmpty(tokens)) {
    //     if (tokens.id_token != undefined) {
    //         validIdToken = await validateToken(tokens.id_token);
    //     }
    //     if (validIdToken == null && (tokens.refresh_token != undefined)) {
    //         tokens = await refreshTokens(tokens.refresh_token);
    //         validIdToken = await validateToken(tokens.id_token);
    //         await setCookies(res, tokens, validIdToken);
    //     }
    // }

    // if (_.isEmpty(req.query) && (req.query.code == undefined) && (validIdToken == null || validIdToken == false)) {
    //     res.render('pages/login', { cognito_login_url: DASHBOARD_COGNITO_LOGIN_URL });
    // }
    // else {
    //     if (req.query.code != undefined && (validIdToken == null || validIdToken == false)) {
    //         //get token
    //         //console.log('call get tokens', validIdToken);
    //         tokens = await getCognitoToken(req.query.code);
    //         if (tokens != null) {
    //             //console.log('validate id_token: ', tokens.id_token);
    //             validIdToken = await validateToken(tokens.id_token); //valid Id token is decoded.
    //             await setCookies(res, tokens, validIdToken);
    //         }
    //     }

    let authResp = await authorize(req, res);
    tokens = authResp.tokens;
    validIdToken = authResp.validIdToken;

    if (validIdToken) {
        let accessLevel = await getAccessLevel(validIdToken);
        if ((accessLevel == cc_employee_admin || accessLevel == cc_employee_cs) && !_.isEmpty(req.body)) {

            //       console.log('req.body: ', req.body);

            let mac = req.body.mac;
            //        console.log('mac: ', mac);

            //let sendStatus = await sendUpdateInfo(mac, part, updateVersion, tokens.id_token);
            let status = await sendNewSessionRequest(mac, tokens.id_token);

            //res.send("Session Start requested!");
            res.send(status);
        }
        else {
            res.send('pages/not_auth');
        }

    }
    else {
        console.log('token is null');
        let devices = null;
        let email = "";
        res.render('pages/login', { cognito_login_url: DASHBOARD_COGNITO_LOGIN_URL });
    }
    //    }
});


app.post('/v3/end_session', async (req, res) => {

    let validIdToken = null;
    let tokens = {};

    // tokens = await getCookieTokens(req);
    // if (!_.isEmpty(tokens)) {
    //     if (tokens.id_token != undefined) {
    //         validIdToken = await validateToken(tokens.id_token);
    //     }
    //     if (validIdToken == null && (tokens.refresh_token != undefined)) {
    //         tokens = await refreshTokens(tokens.refresh_token);
    //         validIdToken = await validateToken(tokens.id_token);
    //         await setCookies(res, tokens, validIdToken);
    //     }
    // }

    // if (_.isEmpty(req.query) && (req.query.code == undefined) && (validIdToken == null || validIdToken == false)) {
    //     res.render('pages/login', { cognito_login_url: DASHBOARD_COGNITO_LOGIN_URL });
    // }
    // else {
    //     if (req.query.code != undefined && (validIdToken == null || validIdToken == false)) {
    //         //get token
    //         //console.log('call get tokens', validIdToken);
    //         tokens = await getCognitoToken(req.query.code);
    //         if (tokens != null) {
    //             //console.log('validate id_token: ', tokens.id_token);
    //             validIdToken = await validateToken(tokens.id_token); //valid Id token is decoded.
    //             await setCookies(res, tokens, validIdToken);
    //         }
    //     }

    let authResp = await authorize(req, res);
    tokens = authResp.tokens;
    validIdToken = authResp.validIdToken;

    if (validIdToken) {
        let accessLevel = await getAccessLevel(validIdToken);
        if ((accessLevel == cc_employee_admin || accessLevel == cc_employee_cs) && !_.isEmpty(req.body)) {

            //       console.log('req.body: ', req.body);

            let mac = req.body.mac;
            //        console.log('mac: ', mac);

            //let sendStatus = await sendUpdateInfo(mac, part, updateVersion, tokens.id_token);
            let status = await sendEndSessionRequest(mac, tokens.id_token);

            //res.send("Session Start requested!");
            res.send(status);
        }
        else {
            res.send('pages/not_auth');
        }

    }
    else {
        console.log('token is null');
        let devices = null;
        let email = "";
        res.render('pages/login', { cognito_login_url: DASHBOARD_COGNITO_LOGIN_URL });
    }
    //    }

});

app.get('/v3/records', async (req, res) => {

    let validIdToken = null;
    let tokens = {};

    // tokens = await getCookieTokens(req);
    // if (!_.isEmpty(tokens)) {
    //     if (tokens.id_token != undefined) {
    //         validIdToken = await validateToken(tokens.id_token);
    //     }

    //     if (validIdToken == null && (tokens.refresh_token != undefined)) {
    //         tokens = await refreshTokens(tokens.refresh_token);
    //         validIdToken = await validateToken(tokens.id_token);
    //         await setCookies(res, tokens, validIdToken);
    //     }
    // }

    // if (_.isEmpty(req.query) && (req.query.code == undefined) && (validIdToken == null)) {
    //     //    console.log('got to login ', DASHBOARD_COGNITO_LOGIN_URL);
    //     res.render('pages/login', { cognito_login_url: DASHBOARD_COGNITO_LOGIN_URL });
    // }
    // else {

    //     if (req.query.code != undefined && validIdToken == null) {
    //         //get token
    //         //console.log('call get tokens');
    //         tokens = await getCognitoToken(req.query.code);
    //         // console.log('validate id_token: ', tokens.id_token);
    //         validIdToken = await validateToken(tokens.id_token); //valid Id token is decoded.
    //         await setCookies(res, tokens, validIdToken);
    //     }

    let authResp = await authorize(req, res);
    tokens = authResp.tokens;
    validIdToken = authResp.validIdToken;

    if (validIdToken) {
        let userUUID = null;
        let email = "";
        let sessionUUID = null;
        let mac = null;
        let timeZone_offset = 0;
        let admin = await checkAdminStatus(validIdToken);
        let rq = req.query;
        let refresh = 0;

        if (!_.isEmpty(rq) && rq.mac != undefined) {

            mac = rq.mac;

            if (rq.sessionId != undefined) {
                sessionUUID = rq.sessionId;
            }
            if (rq.uuid != undefined) {
                //         console.log("rq.uuid ", rq.uuid);
                userUUID = rq.uuid;
            }
            if (rq.tz_offset != undefined) {
                timeZone_offset_minutes = rq.tz_offset;
                //         console.log('time zone offset: ', timeZone_offset_minutes);
            }
            if (rq.refresh != undefined) {
                refresh = rq.refresh;
            }
        }


        let sessionInfo = null;
        let records = {};
        //  console.log("userUUID: ", userUUID);

        if (userUUID == null || userUUID == "") {
            let liveSession = await getLiveSession(tokens, mac);
            sessionInfo = liveSession.data.session;
            // console.log("Live Session Info: ", liveSession);
            delete liveSession.data.session;
            delete liveSession.data.mac;
            records.data = liveSession.data;
            //console.log("record data ", JSON.stringify(records.data));
        }
        else {
            console.log("call getUserSessions");
            let sessionsData = await getUserSessions(tokens, userUUID);
            //get specific session data from sessionsData
            sessionsData.sessions.forEach(session => {
                if (session.session_uuid == sessionUUID) {
                    //    console.log("session info: ", session);
                    sessionInfo = session;
                    return;
                }
            });
            records = await getSessionData(tokens, sessionUUID, mac)
        }

        let deviceInfo = await getDeviceInfo(mac, tokens.id_token);
        console.log("device Info: ", deviceInfo);

        let tempMin = deviceInfo.shadow.state.desired.characteristic.setting.temp_min;

        let localStart = new Date(parseInt(sessionInfo.start_time) - parseInt(timeZone_offset_minutes * 60 * 1000));
        sessionInfo.localStartDateTime = localStart.toLocaleDateString('us-EN') + ' ' + localStart.toLocaleTimeString('us-EN');
        sessionInfo.refresh = refresh;

        // console.log('records.data : ', records.data);

        let recordKeys = Object.keys(records.data);
        // console.log(recordKeys);

        let recordData = {};
        let mode = [];
        let grillTemps = [];
        let setTemps = [];
        let smoke = [];
        let fan = [];
        let p1 = [];
        let g1 = [];
        let p2 = [];
        let g2 = [];
        let p3 = [];
        let g3 = [];
        let p4 = [];
        let g4 = [];
        let millisecLables = [];

        recordKeys.forEach(key => {
            if (key != 'session' && key != 'mac') {

                millisecLables.push(parseInt(key));

                if (records.data[key].mode != undefined) {
                    mode.push(records.data[key].mode);
                }

                if (records.data[key].grill != undefined) {
                    grillTemps.push(records.data[key].grill);

                    if ((records.data[key].mode == undefined || records.data[key].mode == RUN_MODE || records.data[key].mode == STARTUP_MODE) && (records.data[key].setTemp == (tempMin - 5))) {
                        //High Smoke
                        setTemps.push(220);
                        smoke.push(3);
                    }
                    else if ((records.data[key].mode == undefined || records.data[key].mode == RUN_MODE || records.data[key].mode == STARTUP_MODE) && (records.data[key].setTemp == (tempMin - 10))) {
                        //Low Smoke
                        setTemps.push(160);
                        smoke.push(2);
                    }
                    else if (records.data[key].mode == undefined || records.data[key].mode == RUN_MODE || records.data[key].mode == STARTUP_MODE) {

                        setTemps.push(records.data[key].setTemp);
                        smoke.push(records.data[key].smoke);
                    }
                    else {
                        setTemps.push(0);
                        smoke.push(0);
                    }

                    if (records.data[key].mode == FAN_MODE) {
                        fan.push(records.data[key].fan);
                    }
                }

                if (records.data[key].p1 != undefined) {
                    p1.push(records.data[key].p1);
                }
                else {
                    records.data[key].p1 = 0;
                    p1.push(records.data[key].p1);
                }
                if (records.data[key].g1 != undefined) {
                    g1.push(records.data[key].g1);
                }
                else {
                    records.data[key].g1 = 0;
                    g1.push(records.data[key].g1);
                }

                if (records.data[key].p2 != undefined) {
                    p2.push(records.data[key].p2);
                }
                else {
                    records.data[key].p2 = 0;
                    p2.push(records.data[key].p2);
                }
                if (records.data[key].g2) {
                    g2.push(records.data[key].g2);
                }
                else {
                    records.data[key].g2 = 0;
                    g2.push(records.data[key].g2);
                }


                //                    if (sessionInfo.num_probes == 4) {
                if (records.data[key].p3 != undefined) {
                    p3.push(records.data[key].p3);
                }
                else {
                    records.data[key].p3 = 0;
                    p3.push(records.data[key].p3);
                }
                if (records.data[key].g3 != undefined) {
                    g3.push(records.data[key].g3);
                }
                else {
                    records.data[key].g3 = 0;
                    g3.push(records.data[key].g3);
                }


                if (records.data[key].p4 != undefined) {
                    p4.push(records.data[key].p4);
                }
                else {
                    records.data[key].p4 = 0;
                    p4.push(records.data[key].p4);
                }
                if (records.data[key].g4) {
                    g4.push(records.data[key].g4);
                }
                else {
                    records.data[key].g4 = 0;
                    g4.push(records.data[key].g4);
                }
                //                 }
            }
        })

        recordData.milliseconds = millisecLables;

        //recordData.labels = grillTempLabels;
        if (grillTemps.length > 0) {
            recordData.grillTemps = grillTemps;
            recordData.setTemps = setTemps;
            recordData.smoke = smoke;
            recordData.fan = fan;
        }

        //console.log("smoke: ", recordData.smoke);
        recordData.p1 = p1;
        recordData.g1 = g1;
        recordData.p2 = p2;
        recordData.g2 = g2;
        //    if (sessionInfo.num_probes == 4) {
        recordData.p3 = p3;
        recordData.g3 = g3;
        recordData.p4 = p4;
        recordData.g4 = g4;
        //    }

        res.render('pages/records', {
            email: email,
            online: null,
            userUUID: userUUID,
            deviceId: "",
            sessionInfo: sessionInfo,
            sessionData: recordData,
            userToken: validIdToken
        });
    }
    else {
        console.log('token is null');
        let devices = null;
        let email = "";
        res.render('pages/login', { cognito_login_url: DASHBOARD_COGNITO_LOGIN_URL });
    }
    //    }
});


app.get('/v3/devices', async (req, res) => {

    let validIdToken = null;
    let tokens = {};

    let devices = null;
    let deviceId = "";
    let email = "";
    let userUUID = "";

    // tokens = await getCookieTokens(req);
    // if (!_.isEmpty(tokens)) {
    //     if (tokens.id_token != undefined) {
    //         validIdToken = await validateToken(tokens.id_token);
    //     }

    //     if (validIdToken == null && (tokens.refresh_token != undefined)) {
    //         tokens = await refreshTokens(tokens.refresh_token);
    //         validIdToken = await validateToken(tokens.id_token);
    //         await setCookies(res, tokens, validIdToken);
    //     }
    // }

    // if (_.isEmpty(req.query) && (req.query.code == undefined) && (validIdToken == null)) {
    //     //console.log('got to login ', DASHBOARD_COGNITO_LOGIN_URL);
    //     res.render('pages/login', { cognito_login_url: DASHBOARD_COGNITO_LOGIN_URL });
    // }
    // else {

    //     if (req.query.code != undefined && validIdToken == null) {
    //         //get token
    //         //console.log('call get tokens');
    //         tokens = await getCognitoToken(req.query.code);
    //         validIdToken = await validateToken(tokens.id_token); //valid Id token is decoded.
    //     }

    let authResp = await authorize(req, res);
    tokens = authResp.tokens;
    validIdToken = authResp.validIdToken;
    if (validIdToken) {
        let accessLevel = await getAccessLevel(validIdToken);
        console.log('access level: ', accessLevel);

        if (validIdToken && accessLevel != cc_customer) {
            await setCookies(res, tokens, validIdToken);

            // let accessLevel = await getAccessLevel(validIdToken);
            // console.log('access level: ', accessLevel);

            if (!_.isEmpty(req.query) && req.query.deviceId != undefined && req.query.deviceId != null) {

                deviceId = req.query.deviceId;
                if (deviceId.length == 4) {
                    let id = deviceId.toLocaleLowerCase();
                    //    console.log(id);
                    deviceId = 'CampChef:' + id.slice(0, 2) + ':' + id.slice(2, 5);
                    //    console.log(deviceId);
                }

                devices = await getDevicesById(deviceId, tokens);
                //   console.log("Got Devices by ID: ", deviceId);

            }

            res.render('pages/index', {
                email: email,
                online: null,
                userUUID: userUUID,
                deviceId: "",
                devices: devices,
                userToken: validIdToken
            });


        } else {
            console.log('token is null');
            let devices = null;
            let email = "";
            res.render('pages/index', {
                email: email,
                online: null,
                userUUID, userUUID,
                deviceId: "",
                devices: devices,
                userToken: validIdToken
            });
        }
    }
    else {
        console.log('token is null');
        let devices = null;
        let email = "";
        res.render('pages/login', { cognito_login_url: DASHBOARD_COGNITO_LOGIN_URL });
    }
});


// app.get('/V3', async (req, res) => {
//     console.log(req);
//     res.render('pages/index');
// });


// app.get('/V3/faq', async (req, res) => {

//     let data = await getFaqs();
//     //console.log("faq", data);
//     res.render('pages/faq', {
//         faqData: data,
//         deviceId: '',
//         email: '',
//         online: null,
//         userToken: ''
//     });
// });

app.get('/v3/login', async (req, res) => {
    res.clearCookie('id_token');
    res.clearCookie('access_token');
    res.clearCookie('refresh_token');
    res.render('pages/login', { cognito_login_url: DASHBOARD_COGNITO_LOGIN_URL });
});

app.get('/v3/logout', async (req, res) => {
    res.clearCookie('id_token');
    res.clearCookie('access_token');
    res.clearCookie('refresh_token');
    res.render('pages/logout', { cognito_login_url: DASHBOARD_COGNITO_LOGOUT_URL });
});

const server = app.listen(8081, '0.0.0.0', () => {
    const host = server.address().address;
    const port = server.address().port;

    console.log("Dashboard App listening at http://%s:%s", host, port);
})