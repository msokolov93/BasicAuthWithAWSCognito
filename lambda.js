const AWS = require('aws-sdk');
const {
  CognitoIdentityProviderClient,
  AdminInitiateAuthCommand,
} = require("/opt/nodejs/node16/node_modules/@aws-sdk/client-cognito-identity-provider");
const client = new CognitoIdentityProviderClient({ region: "eu-central-1" });

exports.handler = async (event, context, callback) => {
    
    let username = event.queryStringParameters.username;
    let password = event.queryStringParameters.password;
    let app_client_id = process.env.app_client_id;
    let app_client_secret = process.env.app_client_secret;
    let user_pool_id = process.env.user_pool_id;
    let hash = await getHash(username, app_client_id, app_client_secret);
        
    let auth = {
        "UserPoolId": user_pool_id,
        "ClientId": app_client_id,
        "AuthFlow": "ADMIN_NO_SRP_AUTH",
        "AuthParameters": {
            "USERNAME": username,
            "PASSWORD": password,
            "SECRET_HASH": hash
        }
    };

    let cognito_response = await requestToken(auth);

    var lambda_response;
    if (cognito_response.startsWith("Error:")){
        lambda_response = {
          statusCode: 401,
          body: JSON.stringify(cognito_response) + "\n input: username = " + username + " password = " + password,
        };
    }
    else {
      lambda_response = {
        statusCode: 200,
        body: JSON.stringify("AccessToken = " + cognito_response),
      };
    }
    return lambda_response;
};

async function getHash(username, app_client_id, app_client_secret){
    const { createHmac } = await import('node:crypto');
    let msg = new TextEncoder().encode(username+app_client_id);
    let key = new TextEncoder().encode(app_client_secret);
    const hash = createHmac('sha256', key)  // TODO should be separate function
               .update(msg)
               .digest('base64');
    return hash;
}

async function requestToken(auth) {
  const command = new AdminInitiateAuthCommand(auth);  
    var authResponse;
  try {
    authResponse = await client.send(command);
  } catch (error) {
    return "Error: " + error;
  }
  return authResponse.AuthenticationResult.AccessToken;
}
