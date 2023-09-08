# User Api Spec

## Register User

Endpoint : POST /api/users

Request Body :

```json
{
  "username" : "developer",
  "password" : "password",
  "name" : "Developer Keren"
}
```

Response Body (Success) :

```json
{
  "data" : "OK"
}
```

Response Body (Failed) :

```json
{
  "data" : "KO",
  "errors" : "Username must not blank, ???"
}
```

## Login User

Endpoint : POST /api/auth/login

Request Body :

```json
{
  "username" : "developer",
  "password" : "password"
}
```

Response Body (Success) :

```json
{
  "data" : {
    "token" : "TOKEN",
    "expiredAt" : 2323232322323 // miliseconds
  }
}
```

Response Body (Failed 401) :

```json
{
  "errors" : "Username or password wrong"
}
```

## Get User

Endpoint : GET /api/users/current

Request Header :

- X-API-TOKEN : Token (Mandatory)

Response Body (Success) :

```json
{
  "data" : {
    "username" : "developerkeren",
    "name" : "Developer Keren"
  }
}
```

Response Body (Failed 401) :

```json
{
  "errors" : "Unauthorized"
}
```

## Update User

Endpoint : PATCH /api/users/current

Request Header :

- X-API-TOKEN : Token (Mandatory)

Request Body :

```json
{
  "name" : "Developer Keren", // put if only want to update name
  "password" : "password" // put if only want to update password
}
```

Response Body (Success) :

```json
{
  "data" : {
    "username" : "developerkeren",
    "name" : "Developer Keren"
  }
}
```

Response Body (Failed 401) :

```json
{
  "errors" : "Unauthorized"
}
```

## Logout User

Endpoint : DELETE /api/auth/logout

Request Header :

- X-API-TOKEN : Token (Mandatory)
  Response Body (Success) :

```json
{
  "data" : "OK"
}
```