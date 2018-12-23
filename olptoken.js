var request = require('superagent');
var crypto = require('crypto');
var OAuth = require('oauth-1.0a');

//generate OAUTH 1.0 header with signature.
function generateSignatureHeader(input, parameters) {
    var request = {
        url: input.url,
        method: input.method,
        data: parameters
    };

    var oauth = new OAuth({
        consumer: {
            public: input.clientId,
            secret: input.clientSecret
        },
        signature_method: input.signatureMethod,
        hash_function: function (base_string, key) {
            return crypto.createHmac('sha256', key).update(base_string).digest('base64');
        }
    });

    var oauth_data = {
        oauth_consumer_key: oauth.consumer.public,
        oauth_nonce: oauth.getNonce(),
        oauth_signature_method: oauth.signature_method,
        oauth_timestamp: oauth.getTimeStamp(),
        oauth_version: '1.0'
    };

    var encodedSignature = oauth.percentEncode(oauth.getSignature(request, null, oauth_data));
    var header = 'OAuth oauth_consumer_key="' + input.clientId + '",oauth_signature_method="' + oauth_data.oauth_signature_method + '",oauth_timestamp="' + oauth_data.oauth_timestamp + '",oauth_nonce="' + oauth_data.oauth_nonce + '"' +
        ',oauth_version="1.0",oauth_signature="' + encodedSignature + '"';

    return header;
}

/**
 * 
 * @param {string} url 
 * @param {string} clientId 
 * @param {string} clientSecret 
 * @returns {Promise} promise resolved in {accessToken:string, bearer:string, expiresIn:int}
 */
async function getToken(url, clientId, clientSecret) {
    return new Promise(
        (resolve, reject) => {
            var formParams = {
                grant_type: "client_credentials"
            };

            var signatureHeader = generateSignatureHeader({
                "method": "POST",
                "url": url,
                "signatureMethod": "HMAC-SHA256",
                "clientId": clientId,
                "clientSecret": clientSecret
            }, formParams);

            request.post(url)
                .set('Authorization', signatureHeader)
                .type('form')
                .send(formParams)
                .end(function (err, res) {
                    // console.error("getToken answers with status status", res.status);
                    if (res.status == 401) {
                        //   console.error("GetToken status error", res.status);
                        let e = new Error(res.headers["www-authenticate"]); // e.message
                        return reject(e);
                    }

                    // res.body, res.headers, res.status
                    if (err) {
                        //console.error("GetClientToken ERROR", err);
                        return reject(err)
                    }

                    //console.log("getFullToken body: ", res.body);
                    resolve(res.body);
                });
        });
}




module.exports = {
    getToken: getToken
}

