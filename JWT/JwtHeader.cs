using System;
using System.Web.Script.Serialization;

namespace Jack.Services.Jwt
{
  /// <summary>
  /// Represents the header of a JSON Web Token.
  /// </summary>
  internal struct JwtHeader
  {
    #region Properties

    /// <summary>
    /// Identifies an object as a JWT.
    /// </summary>
    [ScriptIgnore]
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
}
