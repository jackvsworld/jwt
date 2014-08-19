/**
JWT for .NET
Written by John Sheehan
(http://john-sheehan.com)
Modified by Andrew Barton
(http://jackvsworld.github.io)
 
This work is public domain.
"The person who associated a work with this document has 
  dedicated the work to the Commons by waiving all of his
  or her rights to the work worldwide under copyright law
  and all related or neighboring legal rights he or she
  had in the work, to the extent allowable by law."
  
For more information, please visit:
http://creativecommons.org/publicdomain/zero/1.0/
*/

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;

namespace Jack.Security
{
  /// <summary>
  /// Specifies the hash algorithm for a JSON Web Token.
  /// </summary>
  public enum JwtHashAlgorithm
  {
    #region Constants

    /// <summary>
    /// HMAC SHA-256.
    /// </summary>
    HS256,

    /// <summary>
    /// HMAC SHA-384.
    /// </summary>
    HS384,

    /// <summary>
    /// HMAC SHA-512.
    /// </summary>
    HS512,

    #endregion
  }

  /// <summary>
  /// Represents the header of a JSON Web Token.
  /// </summary>
  internal struct JwtHeader
  {
    #region Properties

    /// <summary>
    /// Identifies an object as a JWT.
    /// </summary>
    public string typ
    {
      get { return "JWT"; }
    }

    /// <summary>
    /// Specifies the cryptographic algorithm used to secure a JWT.
    /// </summary>
    public string alg { get; set; }

    #endregion
  }

  /// <summary>
  /// Provides methods for encoding and decoding JSON Web Tokens.
  /// </summary>
  /// <remarks>
  /// draft-ietf-oauth-json-web-token
  /// </remarks>
  public abstract class JsonWebToken
  {
    #region Constants

    /// <summary>
    /// The epoch used for calculating for JWT datetime values.
    /// </summary>
    /// <remarks>
    /// January 1, 1970
    /// </remarks>
    public static readonly DateTime Epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    private static readonly Encoding encoding = Encoding.UTF8;
    private static readonly JavaScriptSerializer json = new JavaScriptSerializer();

    #endregion

    /// <summary>
    /// Encodes a JWT.
    /// </summary>
    /// <param name="key">The key used to sign the JWT.</param>
    /// <param name="algorithm">Specifies which hash algorithm to use.</param>
    /// <returns>The generated JWT.</returns>
    public string Encode(string key, JwtHashAlgorithm algorithm)
    {
      return JsonWebToken.Encode(this, key, algorithm);
    }

    /// <summary>
    /// Decodes a JWT, verifies the signature, and returns the JSON payload as an object.
    /// </summary>
    /// <typeparam name="T">The type of object to return.</typeparam>
    /// <param name="token">The JWT.</param>
    /// <param name="key">The key used to sign the JWT.</param>
    /// <returns>An object containing the JWT payload.</returns>
    /// <exception cref="System.ArgumentNullException"><paramref name="token"/> is <c>null</c>.</exception>
    /// <exception cref="System.FormatException">The JWT is not formatted correctly.</exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">The signature is invalid, or the JWT is signed with an unsupported algorithm.</exception>
    public static T Decode<T>(string token, string key)
    {
      return JsonWebToken.Decode<T>(token, key, true);
    }

    /// <summary>
    /// Decodes a JWT, verifies the signature, and returns the JSON payload as an object.
    /// </summary>
    /// <typeparam name="T">The type of object to return.</typeparam>
    /// <param name="token">The JWT.</param>
    /// <param name="key">The key used to sign the JWT.</param>
    /// <param name="verify">Specifies whether to verify the signature.</param>
    /// <returns>An object containing the JWT payload.</returns>
    /// <exception cref="System.ArgumentNullException"><paramref name="token"/> is <c>null</c>.</exception>
    /// <exception cref="System.FormatException">The JWT is not formatted correctly.</exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException"><paramref name="verify"/> is <c>true</c> and the signature is invalid, or the JWT is signed with an unsupported algorithm.</exception>
    public static T Decode<T>(string token, string key, bool verify)
    {
      return json.Deserialize<T>(JsonWebToken.Decode(token, key, verify));
    }

    /// <summary>
    /// Decodes a JWT, verifies the signature, and returns the JSON payload as a <c>string</c>.
    /// </summary>
    /// <param name="token">The JWT.</param>
    /// <param name="key">The key used to sign the JWT.</param>
    /// <param name="verify">Specifies whether to verify the signature.</param>
    /// <returns>A JSON <c>string</c> containing the JWT payload.</returns>
    /// <exception cref="System.ArgumentNullException"><paramref name="token"/> is <c>null</c>.</exception>
    /// <exception cref="System.FormatException">The JWT is not formatted correctly.</exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException"><paramref name="verify"/> is <c>true</c> and the signature is invalid, or the JWT is signed with an unsupported algorithm.</exception>
    public static string Decode(string token, string key, bool verify)
    {
      return JsonWebToken.Decode(token, encoding.GetBytes(key), verify);
    }

    #region Private methods

    private static string Encode(object payload, byte[] key, JwtHashAlgorithm algorithm)
    {
      var segments = new List<string>(3);
      var header = new JwtHeader { alg = algorithm.ToString() };
      byte[] headerBytes = encoding.GetBytes(json.Serialize(header));
      byte[] payloadBytes = encoding.GetBytes(json.Serialize(payload));

      // Get the JWT header and payload
      segments.Add(Base64UrlEncode(headerBytes));
      segments.Add(Base64UrlEncode(payloadBytes));

      using (var sha = GetHashFunction(algorithm, key))
      {
        string stringToSign = String.Join(".", segments.ToArray());
        byte[] signature = sha.ComputeHash(encoding.GetBytes(stringToSign));

        // Get the hash signature for the JWT
        segments.Add(Base64UrlEncode(signature));

        // Join all the segments together and return the complete JWT
        return String.Join(".", segments.ToArray());
      }
    }

    private static string Encode(object payload, string key, JwtHashAlgorithm algorithm)
    {
      return JsonWebToken.Encode(payload, encoding.GetBytes(key), algorithm);
    }

    private static string Decode(string token, byte[] key, bool verify)
    {
      if (token == null)
        throw new ArgumentNullException("token");

      string[] parts = token.Split('.');
      string header;
      string payload;
      byte[] crypto;

      try
      {
        header = parts[0];
        payload = parts[1];
        crypto = Base64UrlDecode(parts[2]);
      }

      catch (IndexOutOfRangeException ex)
      {
        // JWT was not formatted correctly
        throw new FormatException("Token was not formatted correctly.", ex);
      }

      string headerJson = encoding.GetString(Base64UrlDecode(header));
      string payloadJson = encoding.GetString(Base64UrlDecode(payload));

      if (verify)
      {
        var headerData = json.Deserialize<Dictionary<string, object>>(headerJson);
        var algorithm = GetHashAlgorithm((string)headerData["alg"]);
        byte[] bytesToSign = encoding.GetBytes(String.Concat(header, ".", payload));

        using (var sha = GetHashFunction(algorithm, key))
        {
          byte[] signature = sha.ComputeHash(bytesToSign);
          string decodedCrypto = Convert.ToBase64String(crypto);
          string decodedSignature = Convert.ToBase64String(signature);

          if (decodedCrypto != decodedSignature)
          {
            throw new CryptographicException(String.Format(CultureInfo.InvariantCulture,
              "Invalid signature. Expected {0} got {1}", decodedCrypto, decodedSignature));
          }
        }
      }

      return payloadJson;
    }

    private static JwtHashAlgorithm GetHashAlgorithm(string algorithm)
    {
      switch (algorithm)
      {
        case "HS256": return JwtHashAlgorithm.HS256;
        case "HS384": return JwtHashAlgorithm.HS384;
        case "HS512": return JwtHashAlgorithm.HS512;
        default: throw new CryptographicException("Algorithm not supported.");
      }
    }

    private static HMAC GetHashFunction(JwtHashAlgorithm algorithm, byte[] key)
    {
      switch (algorithm)
      {
        case JwtHashAlgorithm.HS256: return new HMACSHA256(key);
        case JwtHashAlgorithm.HS384: return new HMACSHA384(key);
        case JwtHashAlgorithm.HS512: return new HMACSHA512(key);
        default: throw new CryptographicException("Algorithm not supported.");
      }
    }

    // from JWT spec
    private static string Base64UrlEncode(byte[] input)
    {
      string output = Convert.ToBase64String(input);
      output = output.Split('=')[0]; // Remove any trailing '='s
      output = output.Replace('+', '-'); // 62nd char of encoding
      output = output.Replace('/', '_'); // 63rd char of encoding
      return output;
    }

    // from JWT spec
    private static byte[] Base64UrlDecode(string input)
    {
      string output = input;
      output = output.Replace('-', '+'); // 62nd char of encoding
      output = output.Replace('_', '/'); // 63rd char of encoding
      switch (output.Length % 4) // Pad with trailing '='s
      {
        case 0: break; // No pad chars in this case
        case 2: output += "=="; break; // Two pad chars
        case 3: output += "="; break;  // One pad char
        default: throw new FormatException("Invalid base64url string.");
      }
      byte[] converted = Convert.FromBase64String(output); // Standard base64 decoder
      return converted;
    }

    #endregion
  }
}
