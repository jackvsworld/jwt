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
    public static readonly DateTime Epoch = new DateTime(1970, 1, 1);

    private static readonly Encoding encoding = Encoding.UTF8;
    private static readonly JavaScriptSerializer json = new JavaScriptSerializer();

    private static readonly Dictionary<JwtHashAlgorithm, Func<byte[], byte[], byte[]>> hashAlgorithms
      = new Dictionary<JwtHashAlgorithm, Func<byte[], byte[], byte[]>>
    {
      { JwtHashAlgorithm.HS256, (key, value) => { using (var sha = new HMACSHA256(key)) { return sha.ComputeHash(value); } } },
      { JwtHashAlgorithm.HS384, (key, value) => { using (var sha = new HMACSHA384(key)) { return sha.ComputeHash(value); } } },
      { JwtHashAlgorithm.HS512, (key, value) => { using (var sha = new HMACSHA512(key)) { return sha.ComputeHash(value); } } },
    };

    #endregion

    /// <summary>
    /// Encodes a JWT.
    /// </summary>
    /// <param name="key">The key used to sign the token.</param>
    /// <param name="algorithm">The hash algorithm to use.</param>
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
    /// <param name="key">The key that was used to sign the JWT.</param>
    /// <returns>An object representing the payload.</returns>
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
    /// <param name="key">The key that was used to sign the JWT.</param>
    /// <param name="verify">Whether to verify the signature.</param>
    /// <returns>An object representing the payload.</returns>
    /// <exception cref="System.ArgumentNullException"><paramref name="token"/> is <c>null</c>.</exception>
    /// <exception cref="System.FormatException">The JWT is not formatted correctly.</exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException"><paramref name="verify"/> is <c>true</c> and the signature is invalid, or the JWT is signed with an unsupported algorithm.</exception>
    public static T Decode<T>(string token, string key, bool verify)
    {
      string payloadJson = JsonWebToken.Decode(token, key, verify);
      T payloadData = json.Deserialize<T>(payloadJson);
      return payloadData;
    }

    #region Private methods

    private static string Encode(object payload, byte[] key, JwtHashAlgorithm algorithm)
    {
      var segments = new List<string>(3);
      var header = new { typ = "JWT", alg = algorithm.ToString() };

      byte[] headerBytes = encoding.GetBytes(json.Serialize(header));
      byte[] payloadBytes = encoding.GetBytes(json.Serialize(payload));

      segments.Add(Base64UrlEncode(headerBytes));
      segments.Add(Base64UrlEncode(payloadBytes));

      string stringToSign = String.Join(".", segments.ToArray());
      byte[] bytesToSign = encoding.GetBytes(stringToSign);
      byte[] signature = hashAlgorithms[algorithm](key, bytesToSign);

      segments.Add(Base64UrlEncode(signature));

      return String.Join(".", segments.ToArray());
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
      var headerData = json.Deserialize<Dictionary<string, object>>(headerJson);

      if (verify)
      {
        byte[] bytesToSign = encoding.GetBytes(String.Concat(header, ".", payload));
        var algorithm = GetHashAlgorithm((string)headerData["alg"]);
        byte[] signature = hashAlgorithms[algorithm](key, bytesToSign);
        string decodedCrypto = Convert.ToBase64String(crypto);
        string decodedSignature = Convert.ToBase64String(signature);

        if (decodedCrypto != decodedSignature)
        {
          throw new CryptographicException(String.Format(CultureInfo.InvariantCulture,
            "Invalid signature. Expected {0} but got {1}", decodedCrypto, decodedSignature));
        }
      }

      return payloadJson;
    }

    private static string Decode(string token, string key, bool verify)
    {
      return JsonWebToken.Decode(token, encoding.GetBytes(key), verify);
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
      return Convert.FromBase64String(output); // Standard base64 decoder
    }

    #endregion
  }
}
