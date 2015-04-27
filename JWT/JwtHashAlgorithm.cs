using System;

namespace Jack.Services.Jwt
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
}
