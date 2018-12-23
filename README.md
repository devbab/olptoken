# OLPTOKEN

## Usage

In Node.js

    const olptoken = require('olptoken');

    token = olptoken.getToken(OLP_TOKEN_URL, OLP_KEY_ID, OLP_KEY_SECRET);
  

In browser
   
    <script src="https://www.unpkg.com/olptoken"> </script>
    
    olpGetToken(OLP_KEY_ID, OLP_KEY_SECRET,
            function cb(data) {
                // token in data.access_token
            });
