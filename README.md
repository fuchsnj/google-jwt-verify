# Google JSON Web Token Verify
[![Build Status](https://travis-ci.org/fuchsnj/google-jwt-verify.svg?branch=master)](https://travis-ci.org/fuchsnj/google-jwt-verify)
[![crates.io](https://img.shields.io/crates/v/google-jwt-verify.svg)](https://crates.io/crates/google-jwt-verify)
[![documentation](https://docs.rs/google-jwt-verify/badge.svg)](https://docs.rs/google-jwt-verify)

This can be used to verify Google JWT tokens. Google's public keys are automatically fetched
and cached according to the returned Cache-Control headers. Most requests to verify a token
through this library will not wait for an HTTP request

This library supports two different Google authentication services: Google Signin and Firebase Authentication.

For more info about Google Signin: https://developers.google.com/identity/sign-in/web/backend-auth

For more info about Firebase Authentication: https://firebase.google.com/docs/auth/admin/verify-id-tokens

The library has two features: `async` and `blocking`. The default is just the `blocking` feature.

## Google Signin Blocking Quick Start
```rust
 //If you don't have a client id, get one from here: https://console.developers.google.com/
 let client_id = "37772117408-qjqo9hca513pdcunumt7gk08ii6te8is.apps.googleusercontent.com";
 let token = "...";// Obtain a signed token from Google
 let client = Client::new_google_signin(&client_id);
 let id_token = client.verify_id_token(&token)?;
 
 //use the token to obtain information about the verified user
 let user_id = id_token.get_claims().get_subject();
 let email = id_token.get_payload().get_email();
 let name = id_token.get_payload().get_name();
```

## Firebase Authentication Blocking Quick Start
```rust
 //If you don't have a firebase project, create one from here: https://firebase.google.com/
 let project_id = "jwt-verify";
 let token = "...";// Obtain a signed token from Google
 let client = Client::new_firebase(&project_id);
 let id_token = client.verify_id_token(&token)?;
 
 //use the token to obtain information about the verified user
 let user_id = id_token.get_claims().get_subject();
```

The `async` feature supports Tokio v0.2 runtime by modifying the above examples. Raise a Github issue if you need other async runtimes supported.

```rust
let client = Client::google_signin_builder(&client_id).tokio().build();
let id_token = client.verify_id_token(&token).await?;
```

```rust
let client = Client::firebase_builder(&project_id).tokio().build();
let id_token = client.verify_id_token(&token).await?;
```
