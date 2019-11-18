# Discourse SSO Connector
![Build Status](https://github.com/jonfriesen/discourse-sso-connector/workflows/build/badge.svg)

This is a HTTP handler generator that will return a middleware and endpoint you can configure against your Discourse to use your site as your identity provider. An example use-case is, say you have a web app already and you want to expose Discourse to your users. With this connector you can easily create an HTTP handler that can be configured with Discourse to use your website for login.

## Things to do
- [ ] Improve test coverage
- [ ] Add AuthHandler writer watcher to detect when an auth handler has closed the writer
- [ ] Add user management options (requires API key) for syncing users, ending sessions
- [ ] Add group support
- [ ] Add custom parameter support

## Using Discourse Connector

This package intends to make integration easier, there are still some pieces that will need to be done on the applications side. The application will need to create an endpoint for signin, an authentication handler, and a endpoint for handling the authentication.

See an basic example in `cmd/discourse-connector-exmaple/main.go`

A Discourse mock server can be used to test your implementation at `cmd/discourse-mock-server/main.go`

### First contact endpoint
Discourse will let you set an endpoint in it's SSO settings. This library is designed so you can take your current signin endpoint, duplicate it under a new path, and wrap it in the `connector.GetValidationMiddleware`. This middleware will validate that your payload and signature match and create a cookie holding these values with a 10 minute expiry.

### Auth Handler function
You will also need to create an auth handler function that matches the following signature:
```go
type AuthHandler func(http.ResponseWriter, *http.Request) (*Response, error)
```
This function should be the handle the auth from your signin page. If the auth was a success, fill out as much of the Response object as you'd like and return it (You don't need to fill out the Nonce, that will be done for you). In the event that user fails authentication you can handle it appropriately (eg. showing an error) as you would normally and return an error to stop the connector logic.

### Handler
The handler acts as a `http.HandlerFunc` and will run the AuthHandler you created after validating the cookie, and it's contents, are valid. After the AuthHandler returns a Response object, the user will be redirected to Discourse with the response that is signed by the connector. The user should now be logged in.

## How this works (under the covers)

1. User visits Discourse protect page and is redirected to auth endpoint:
    1. A Nonce is generated
    2. Nonce is made into payload (eg `nonce=cb68251eefb5211e58c00ff1395f0c0b`)
    3. Payload is Base64 encoded (eg. `bm9uY2U9Y2I2ODI1MWVlZmI1MjExZTU4YzAwZmYxMzk1ZjBjMGI=\n`)
    4. Payload is URL encoded (eg. `bm9uY2U9Y2I2ODI1MWVlZmI1MjExZTU4YzAwZmYxMzk1ZjBjMGI%3D%0A`)
    5. HMAC-SHA256 is generated (eg. `2828aa29899722b35a2f191d34ef9b3ce695e0e6eeec47deb46d588d70c7cb56`)
    6. User is redirected to our auth page with the URL format: `http://www.example.com/discourse/sso?sso=bm9uY2U9Y2I2ODI1MWVlZmI1MjExZTU4YzAwZmYxMzk1ZjBjMGI%3D%0A&sig=2828aa29899722b35a2f191d34ef9b3ce695e0e6eeec47deb46d588d70c7cb56`

2. Our Auth endpoint is hit at the above URL and we start the authentication process

    1. Using the `GetValidationMiddleware` middleware we wrap the apps sign in page which should be under a custom endpoint. If the payload and signature from Discourse match we will add them to a cookie with a 10 minute expiry.

    2. The apps sign in logic takes over at this point (see our section below on setting up your auth page)
        - The app will provide an auth handler function that will do the actual authentication and returns a `connector.Response` object, the auth handler function looks like `func(http.ResponseWriter, *http.Request) (*Response, error)`
        - If the auth fails, you can handle it as you normally would and return an error which will stop the Discourse log in (eg. redirect the user to an error page)

    3. Once auth is complete we fill out the response payload for Discourse (see our section on response payload specs)
    eg: 
        ```
        name: sam
        external_id: hello123
        email: test@test.com
        username: samsam
        require_activation: true
        ```

    4. Conver the response payload to a string (eg. `nonce=cb68251eefb5211e58c00ff1395f0c0b&name=sam&username=samsam&email=test%40test.com&external_id=hello123&require_activation=true`)

    5. Base64 encode the response payload (eg. `bm9uY2U9Y2I2ODI1MWVlZmI1MjExZTU4YzAwZmYxMzk1ZjBjMGImbmFtZT1zYW0mdXNlcm5hbWU9c2Ftc2FtJmVtYWlsPXRlc3QlNDB0ZXN0LmNvbSZleHRlcm5hbF9pZD1oZWxsbzEyMyZyZXF1aXJlX2FjdGl2YXRpb249dHJ1ZQ==`)

    6. Generate the HMAC-256 signature or the Base64 encoded response payload
    7. URL encode the response payload (eq. `bm9uY2U9Y2I2ODI1MWVlZmI1MjExZTU4YzAwZmYxMzk1ZjBjMGImbmFtZT1zYW0mdXNlcm5hbWU9c2Ftc2FtJmVtYWlsPXRlc3QlNDB0ZXN0LmNvbSZleHRlcm5hbF9pZD1oZWxsbzEyMyZyZXF1aXJlX2FjdGl2YXRpb249dHJ1ZQ%3D%3D`)
    
    8. Redirect the user back to Discourse with the payload and signature (eg. `http://discuss.example.com/session/sso_login?sso=bm9uY2U9Y2I2ODI1MWVlZmI1MjExZTU4YzAwZmYxMzk1ZjBjMGImbmFtZT1zYW0mdXNlcm5hbWU9c2Ftc2FtJmVtYWlsPXRlc3QlNDB0ZXN0LmNvbSZleHRlcm5hbF9pZD1oZWxsbzEyMyZyZXF1aXJlX2FjdGl2YXRpb249dHJ1ZQ%3D%3D&sig=9cac76783c69a5dbf0d424d9d7e3a54aea973bada2e4eb2739e8d5ff2a2dc4c4`)

## Response Payload specs
Payload structure is:
```go
type Response struct {
	Nonce              string `url:"nonce"`
	ExternalID         string `url:"external_id"`
	Email              string `url:"email"`
	Name               string `url:"name,omitempty"`
	Username           string `url:"username,omitempty"`
	RequireActivation  bool   `url:"require_activation,omitempty"`
	AvatarURL          string `url:"avatar_url,omitempty"`
	AvatarForceUpdate  bool   `url:"avatar_force_update,omitempty"`
	Bio                bool   `url:"bio,omitempty"`
	IsAdmin            bool   `url:"admin,omitempty"`
	IsModerator        bool   `url:"moderator,omitempty"`
	SuppressWelcomeMsg bool   `url:"suppress_welcome_message,omitempty"`
}
```
Payload specs are as follows:
- nonce should be copied from the input payload
- email must be a verified email address. If the email address has not been verified, set require_activation to “true”.
- external_id is any string unique to the user that will never change, even if their email, name, etc change. The suggested value is your database’s ‘id’ row number.
- username will become the username on Discourse if the user is new or SiteSetting.sso_overrides_username is set.
- name will become the full name on Discourse if the user is new or SiteSetting.sso_overrides_name is set.
- avatar_url will be downloaded and set as the user’s avatar if the user is new or SiteSetting.sso_overrides_avatar is set.
- avatar_force_update is a boolean field. If set to true, it will force Discourse to update the user’s avatar, whether avatar_url has changed or not.
- bio will become the contents of the user’s bio if the user is new, their bio is empty or SiteSetting.sso_overrides_bio is set.
- Additional boolean (“true” or “false”) fields are: admin, moderator, suppress_welcome_message

## References
Thanks to Sam Saffron (co-founder of Discourse) for writing an amazing overview doc of the [Disources SSO Implementation](https://meta.discourse.org/t/official-single-sign-on-for-discourse-sso/13045)