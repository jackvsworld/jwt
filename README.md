JSON Web Tokens for .NET
========================

This library supports generating and decoding [JSON Web Tokens](http://tools.ietf.org/html/draft-jones-json-web-token-10).

Defining Tokens
---------------

A typical JWT might contain some of the following claims:

    public class MyWebToken : JsonWebToken
    {
      public string iss { get; set; }  /* issuer */
      public string sub { get; set; }  /* subject */
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

Verifying and Decoding Tokens
-----------------------------

The following code demonstrates how to verify and decode a JWT:

    try
    {
      string jwt = JsonWebToken.Decode(token, "MY_SECRET_KEY", true);
      Console.WriteLine(jwt);
    }
    
    catch (FormatException)
    {
      Console.WriteLine("Invalid token!");
    }
    
    catch (CryptographicException)
    {
      Console.WriteLine("Signature mismatch!");
    }

Example output:

    { "iss": "www.example.com", "sub": "jack@example.com", "exp": /Date(1408354887)/ }
