# go oauth

## Resources

* oauth2 tutorial by medium [tutorial](https://medium.com/@cyantarek/build-your-own-oauth2-server-in-go-7d0f660732c3)
* go oauth [source](https://github.com/go-oauth2/oauth2)
* Authentication in Golang with JWTs [tutorial](https://auth0.com/blog/authentication-in-golang/)
* oauth2 tutorial [tutorial](https://tutorialedge.net/golang/go-oauth2-tutorial/)
| [code source](https://github.com/go-oauth2/oauth2/tree/master/example) 
| [code source](https://github.com/TutorialEdge/go-oauth-tutorial)
* How to mock OAuth 2.0 in Go [tutorial](https://blog.seriesci.com/how-to-mock-oauth-in-go/)

## Command

- `make server` - launch the app

## Protocol Flow

```text
     +--------+                               +---------------+
     |        |--(A)- Authorization Request ->|   Resource    |
     |        |                               |     Owner     |
     |        |<-(B)-- Authorization Grant ---|               |
     |        |                               +---------------+
     |        |
     |        |                               +---------------+
     |        |--(C)-- Authorization Grant -->| Authorization |
     | Client |                               |     Server    |
     |        |<-(D)----- Access Token -------|               |
     |        |                               +---------------+
     |        |
     |        |                               +---------------+
     |        |--(E)----- Access Token ------>|    Resource   |
     |        |                               |     Server    |
     |        |<-(F)--- Protected Resource ---|               |
     +--------+                               +---------------+
     |        |
     |        |                               +---------------+
     |        |--(E)---- Refresh Token ------>| Authorization |
     |        |                               |     Server    |
     |        |<-(F)---  Access Resource   ---|               |
     +--------+                               +---------------+
```

## Test

Open and set your credentials :

>http://localhost:9096/login

that return :

```
{
"access_token": "IXW4T64OO022LZYMMHYQNG",
"expires_in": 7200,
"scope": "all",
"token_type": "Bearer"
}
```

Take your token and call

> http://localhost:9096/protected?access_token=IXW4T64OO022LZYMMHYQNG
