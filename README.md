
This code uses reflective access, make sure your version of Java supports/allows this!
We used JAVA_VERSION="15.0.2"

To run the server, run the following: \
( make sure to replace <path-to-Java-Home> and <path-to-sbp_impl-root-dir> )

```
<path-to-Java-Home>\Java\bin\java.exe
    --illegal-access=permit 
    -classpath <path-to-sbp_impl-root-dir>\sbp_impl\out\production\sbp_impl 
    sbp.HTTPS_Server
```

Make sure to import `certs\myCA.pem` as a Certificate Authority into your browser / System Certificates

Using a browser, visit `https://localhost:9000/login` \
Click the button to simulate the login / client authentication process. \
You will be given an application session token in the form of a cookie, \
and you will be taken to the account landing page. \
This page includes malicious code that will forge and send a state-changing request to the server. \
You can check the server output in the terminal to see if the server will honor or ignore this malicious request.

General information about this implementation:
1. There are 3 endpoints for this server:\
   1. The `/login` endpoint takes the user to the `Login` page \
   2. The `/account` endpoint is the user's `Account` landing page \
   3. The `/change` endpoint accepts state-changing requests for the account
2. When the user clicks on the button in the `Login` page, \
they are direct to the `/account` endpoint and the server does the following:
   1. The server uses Java's illegal reflective access to extract the master secret used with each client \
      (this will generate a warning in the terminal, you can ignore that warning)
   2. The server uses the master secret and a constant secret key `KPS` to generate a `clientKey` for each client
   3. The server generates and stores a new token for each client
   4. The server generates a fresh IV and encrypts the token using the `clientKey`
   5. The server attaches the encrypted token as a cookie to the response
   6. The server attaches the html for the `Account` page as the body of the response and send the response.
3. The `Account` page includes injected malicious JavaScript code. \
   When the page loads inside the client's browser, the code runs and sends a request to the `/change` endpoint. \
   The browser will auto-attach the cookie received from the server to this change request
4. When the server receives a request on the `/change` endpoint, it does the following:
   1. The server searches for a cookie, if not found, request is ignored, otherwise:
   2. The server regenerates the `clientKey` for client and uses it to decrypt the value stored in the cookie
   3. If the decrypted value is found in the stored list of issued tokens, \
      the server prints `Valid change request received, request will be honored!` \
      otherwise, it prints `Invalid change request received, request will be ignored`

