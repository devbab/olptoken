/**
 * 
 * @param {string} clientId 
 * @param {string} clientSecret 
 * @returns token
 */
function olpGetToken(clientId, clientSecret, cb) {

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
                // return crypto.createHmac('sha256', key).update(base_string).digest('base64');
                var hash = CryptoJS.HmacSHA256(base_string, key);
                var hashInBase64 = CryptoJS.enc.Base64.stringify(hash);
                return hashInBase64;
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

    var url = "https://account.api.here.com/oauth2/token";

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


    var https = new XMLHttpRequest();
    https.open('POST', url, true);

    //Send the proper header information along with the request
    https.setRequestHeader('Accept', '*/*');
    https.setRequestHeader('Authorization', signatureHeader);
    https.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8');

    https.onreadystatechange = function () {//Call a function when the state changes.
        if (https.readyState == 4 && https.status == 200) {
            cb(JSON.parse(https.responseText));
        }
    }
    https.send("grant_type=client_credentials");
}


