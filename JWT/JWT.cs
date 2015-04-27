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
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;

namespace Jack.Services.Jwt
{
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
    public static readonly DateTime Epoch = new DateTime(1970, 1, 1);

    private static readonly Encoding encoding = Encoding.UTF8;
    private static readonly JavaScriptSerializer jss = new JavaScriptSerializer();

    #endregion

    /// <summary>
    /// Decodes a JSON Web Token.
    /// </summary>
    /// <typeparam name="T">The type of object to return.</typeparam>
    /// <param name="token">The JWT.</param>
    /// <returns>An object containing the JWT payload.</returns>
    /// <exception cref="System.ArgumentNullException"><paramref name="token"/> is <c>null</c>.</exception>
    /// <exception cref="System.FormatException">The JWT is not formatted correctly.</exception>
    /// <remarks>
    /// This method does not guarantee the integrity of the data contained in the token.
    /// You should call the <see cref="Jack.Services.Jwt.JsonWebToken.Verify"/> method to ensure that the token has not been tampered with.
    /// </remarks>
    public static T Decode<T>(string token)
    {
      return jss.Deserialize<T>(JsonWebToken.Decode(token));
    }

    /// <summary>
    /// Verifies a JSON Web Token.
    /// </summary>
    /// <param name="token">The JWT.</param>
    /// <param name="key">The key used to sign the JWT.</param>
    /// <returns><c>true</c> is the JWT is valid, otherwise <c>false</c>.</returns>
    /// <exception cref="System.ArgumentNullException"><paramref name="token"/> is <c>null</c>.</exception>
    /// <exception cref="System.FormatException">The JWT is not formatted correctly.</exception>
    public static bool Verify(string token, string key)
    {
      return JsonWebToken.Verify(token, encoding.GetBytes(key));
    }

    /// <summary>
    /// Encodes a JSON Web Token.
    /// </summary>
    /// <param name="key">The key used to sign the JWT.</param>
    /// <param name="algorithm">Specifies which hash algorithm to use.</param>
    /// <returns>The generated JWT.</returns>
    public virtual string Encode(string key, JwtHashAlgorithm algorithm)
    {
      return JsonWebToken.Encode(this, encoding.GetBytes(key), algorithm);
    }

    #region Private methods

    private static string[] GetSegments(string token)
    {
      string[] segments = token.Split('.');

      // Split into segments
      if (segments.Length == 3)
        return segments;

      // The JWT must have exactly 3 segments
      throw new FormatException(Properties.Resources.InvalidJwt);
    }

    private static string Decode(string token)
    {
      if (token == null)
        throw new ArgumentNullException("token");

      string[] segments = GetSegments(token);

      // Decode the JWT payload and return a JSON string
      return encoding.GetString(Jack.Text.Base64Url.FromBase64String(segments[1]));
    }

    private static bool Verify(string token, byte[] key)
    {
      if (token == null)
        throw new ArgumentNullException("token");

      string[] segments = GetSegments(token);
      var algorithm = DecodeHeader(segments[0]);

      using (var sha = GetHashFunction(algorithm, key))
      {
        string data = segments[0] + "." + segments[1];
        byte[] hash = sha.ComputeHash(encoding.GetBytes(data));

        // Determine whether the hash signatures are equal
        return Jack.Text.Base64Url.ToBase64String(hash).Equals(segments[2]);
      }
    }

    private static string Encode(object payload, byte[] key, JwtHashAlgorithm algorithm)
    {
      var segments = new string[2];
      var header = new JwtHeader { alg = algorithm.ToString() };
      byte[] headerBytes = encoding.GetBytes(jss.Serialize(header));
      byte[] payloadBytes = encoding.GetBytes(jss.Serialize(payload));

      // Get the JWT header and payload
      segments[0] = Jack.Text.Base64Url.ToBase64String(headerBytes);
      segments[1] = Jack.Text.Base64Url.ToBase64String(payloadBytes);

      using (var sha = GetHashFunction(algorithm, key))
      {
        string data = String.Join(".", segments);
        byte[] hash = sha.ComputeHash(encoding.GetBytes(data));
        string signature = Jack.Text.Base64Url.ToBase64String(hash);

        // Join the header, payload and signature to create a JWT
        return String.Join(".", segments.Concat(new [] { signature }).ToArray());
      }
    }

    private static JwtHashAlgorithm DecodeHeader(string header)
    {
      byte[] data = Jack.Text.Base64Url.FromBase64String(header);

      // Get the hash algorithm from the JWT header
      return GetHashAlgorithm(jss.Deserialize<JwtHeader>(encoding.GetString(data)).alg);
    }

    private static JwtHashAlgorithm GetHashAlgorithm(string algorithm)
    {
      switch (algorithm)
      {
        case "HS256": return JwtHashAlgorithm.HS256;
        case "HS384": return JwtHashAlgorithm.HS384;
        case "HS512": return JwtHashAlgorithm.HS512;
        default: throw new CryptographicException(Properties.Resources.InvalidJwtAlgorithm);
      }
    }

    private static HMAC GetHashFunction(JwtHashAlgorithm algorithm, byte[] key)
    {
      switch (algorithm)
      {
        case JwtHashAlgorithm.HS256: return new HMACSHA256(key);
        case JwtHashAlgorithm.HS384: return new HMACSHA384(key);
        case JwtHashAlgorithm.HS512: return new HMACSHA512(key);
        default: throw new CryptographicException(Properties.Resources.InvalidJwtAlgorithm);
      }
    }

    #endregion
  }
}
