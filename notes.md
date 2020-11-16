
## Get a Token using credentials

curl -d "client_id=admin-cli" -d "username=admin" -d "password=adminpw" -d "grant_type=password" -k "https://localhost:8443/auth/realms/master/protocol/openid-connect/token"



## Get a Token (incl. ID Token) using credentials

curl -d "client_id=admin-cli" -d "username=admin" -d "password=adminpw" -d "grant_type=password" -d "scope=openid" -d "response_type=id_token" -k "https://localhost:8443/auth/realms/master/protocol/openid-connect/token"



## Get an Offline Token using credentials

curl -d "client_id=admin-cli" -d "username=admin" -d "password=adminpw" -d "grant_type=password" -d "scope=offline_access" -k "https://localhost:8443/auth/realms/master/protocol/openid-connect/token"



## Get a Token (incl. ID Token) via login > redirect > access_code

https://localhost:8443/auth/realms/simple/protocol/openid-connect/auth?client_id=myclient&redirect_uri=http://localhost/test&scope=openid&response_type=code

redirect -> ``http://localhost/test
              ?session_state=bla
              &code=xyz``

use code to obtain token -> 
``curl -d "client_id=myclient" -d "redirect_uri=http://localhost/test" -d "grant_type=authorization_code" -d "code=xyz" -k "https://localhost:8443/auth/realms/simple/protocol/openid-connect/token"``



## Get User Info

curl -d "access_token=abc" -k "https://localhost:8443/auth/realms/simple/protocol/openid-connect/userinfo"



## Realm Info (incl. public key)

https://localhost:8443/auth/realms/simple

https://localhost:8443/auth/realms/simple/.well-known/openid-configuration



## User Account UI (incl. linking accounts)

https://localhost:8443/auth/realms/simple/account



## Admin REST API examples

curl -X GET --header "Content-Type: application/json" --header "Authorization: bearer abc" -k "https://localhost:8443/auth/admin/realms/simple"

curl -X PUT --header "Content-Type: application/json" --header "Authorization: bearer abc" -d '{"id":"master","realm":"master",...}' -k "https://localhost:8443/auth/admin/realms/master"

curl -X POST --header "Content-Type: application/json" --header "Authorization: bearer abc" -d '{"id":"simple","realm":"simple",...}' -k "https://localhost:8443/auth/admin/realms"

curl -X GET --header "Content-Type: application/json" --header "Authorization: bearer abc" -k "https://localhost:8443/auth/admin/realms/simple/identity-provider/instances"

curl -X POST --header "Content-Type: application/json" --header "Authorization: bearer abc" -d '{"alias":"helmholtz-berlin.de",...}' -k "https://localhost:8443/auth/admin/realms/simple/identity-provider/instances"

curl -X GET --header "Content-Type: application/json" --header "Authorization: bearer abc" -k "https://localhost:8443/auth/admin/realms/simple/clients"

curl -X POST --header "Content-Type: application/json" --header "Authorization: bearer abc" -d '{"id":"918d2fec-f8e7-40d9-a9d1-cc2c38023b35",...}' -k "https://localhost:8443/auth/admin/realms/simple/clients"

curl -X GET --header "Content-Type: application/json" --header "Authorization: bearer abc" -k "https://localhost:8443/auth/admin/realms/simple/users"

curl -X GET --header "Content-Type: application/json" --header "Authorization: bearer abc" -k "https://localhost:8443/auth/admin/realms/simple/users/XXX/federated-identity"

curl -X GET --header "Content-Type: application/json" --header "Authorization: bearer abc" -k "https://localhost:8443/auth/admin/realms/simple/users/XXX/configured-user-storage-credential-types"

curl -X PUT --header "Content-Type: application/json" --header "Authorization: bearer abc" -d '{"value":"testpw"}' -k "https://localhost:8443/auth/admin/realms/simple/users/XXX/reset-password"

curl -X PUT --header "Content-Type: application/json" --header "Authorization: bearer abc" -d '["UPDATE_PASSWORD"]' -k "https://localhost:8443/auth/admin/realms/simple/users/XXX/execute-actions-email"





## Useful links etc.

### Token decoder tool
https://jwt.io/

### Java JWT Tokens
https://medium.com/trabe/validate-jwt-tokens-using-jwks-in-java-214f7014b5cf

### Python JWT Tokens
https://stackoverflow.com/questions/53860030/how-to-use-pyjwt-to-verify-signature-on-this-jwt

https://requests-oauthlib.readthedocs.io/en/latest/examples/real_world_example.html

https://github.com/jpadilla/pyjwt/issues/359

### Start Keycloak command
./standalone.sh -b 0.0.0.0 -bmanagement 0.0.0.0 -Djboss.socket.binding.port-offset=100 -Djboss.management.http.port=8124

docker run --rm -ti -d -p 8080:8080 -p 8443:8443 -p 9990:9990 -e DB_VENDOR=h2 -e KEYCLOAK_USER=admin -e KEYCLOAK_PASSWORD=adminpw jboss/keycloak -b 0.0.0.0 -bmanagement 0.0.0.0

### DFN-AAI Test
https://doku.tid.dfn.de/de:functionaltest_sp

https://testsp2.aai.dfn.de/secure-all