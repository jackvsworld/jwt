JSON Web Tokens for .NET
========================

Provides support for generating and decoding [JSON Web Tokens](https://tools.ietf.org/html/draft-ietf-oauth-json-web-token).

Defining Tokens
---------------

A typical JWT might contain some of the following claims:

    public class MyWebToken : JsonWebToken
    {
        public string iss { get; set; }  /* issuer */
        public string aud { get; set; }  /* audience */
        public string sub { get; set; }  /* subject */
        public long iat { get; set; }    /* timestamp */
        public long exp { get; set; }    /* expiration time */
    }
    
To define a JWT, simply create a subclass of `JsonWebToken` and add a property for each claim that you want to use.

Creating Tokens
---------------

The following code creates a JWT with an expiration time of two hours:

    var expires = DateTime.UtcNow.AddHours(2.0);
    var jwt = new MyWebToken
    {
        iss = "www.example.com",
        sub = "jack@example.com",
        exp = Convert.ToInt64(expires.Subtract(JsonWebToken.Epoch).TotalSeconds),
    };
    
    string token = jwt.Encode("MY_SECRET_KEY", JwtHashAlgorithm.HS256);
    Console.WriteLine(token);

Example output:

    eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ3d3cuZXhhbXBsZS5jb20iLCJzdWIiOiJqYWNrQGV4YW1wbGUuY29tIiwiZXhwIjoxNDA4MzU0ODg3fQ.sfa_JUbOlYL7eY8M1GnctXXVJWaaec9M3kvJDpkeir4
    
Verifying Tokens
----------------

The following code demonstrates how to verify a JWT:

    try
    {
        bool verified = JsonWebToken.Verify(token, "MY_SECRET_KEY");
        Console.WriteLine(verified);
    }
    
    catch (FormatException)
    {
        Console.WriteLine("Invalid token!");
    }
    
    catch (CryptographicException)
    {
        Console.WriteLine("Invalid signature algorithm!");
    }

Example output:

    True

Verification is used to determine whether a JWT is authentic. You should always verify JWTs to ensure that the data hasn't been tampered with.

Decoding Tokens
---------------

The following code demonstrates how to decode a JWT:

    try
    {
        MyWebToken jwt = JsonWebToken.Decode<MyWebToken>(token);
        Console.WriteLine("Issuer:  " + jwt.iss);
        Console.WriteLine("Subject: " + jwt.sub);
        Console.WriteLine("Expires: " + jwt.exp);
    }
    
    catch (FormatException)
    {
        Console.WriteLine("Invalid token!");
    }
    
Example output:

    Issuer:  www.example.com
    Subject: jack@example.com
    Expires: 1418222868

Complete Example
----------------

The following code demonstrates how to verify and decode a JWT:

    try
    {
        if (JsonWebToken.Verify(token, "MY_SECRET_KEY"))
        {
            MyWebToken jwt = JsonWebToken.Decode<MyWebToken>(token);
            ...
        }
    }
    
    catch (FormatException)
    {
        Console.WriteLine("Invalid token!");
    }
    
    catch (CryptographicException)
    {
        Console.WriteLine("Invalid signature algorithm!");
    }
