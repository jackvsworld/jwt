using System;
using System.Text;

namespace Jack.Text
{
  /// <summary>
  /// Provides methods for encoding and decoding Base64 data.
  /// </summary>
  /// <remarks>
  /// RFC 4648 §5
  /// </remarks>
  public static class Base64Url
  {
    /// <summary>
    /// Converts a <c>byte</c> array to a <c>string</c> using Base64url encoding.
    /// </summary>
    /// <param name="input">A <c>byte</c> array.</param>
    /// <returns>A Base64url-encoded <c>string</c>.</returns>
    public static string ToBase64String(byte[] input)
    {
      return Convert.ToBase64String(input)
        .TrimEnd('=') // Remove pad chars
        .Replace('+', '-')  // 62nd char of encoding
        .Replace('/', '_'); // 63rd char of encoding
    }

    /// <summary>
    /// Converts a <c>string</c> to a <c>byte</c> array using Base64url encoding.
    /// </summary>
    /// <param name="input">A Base64url-encoded <c>string</c>.</param>
    /// <returns>A <c>byte</c> array.</returns>
    /// <exception cref="System.FormatException"><paramref name="input"/> contains invalid Base64url characters.</exception>
    public static byte[] FromBase64String(string input)
    {
      string output = input
        .Replace('-', '+')  // 62nd char of encoding
        .Replace('_', '/'); // 63rd char of encoding

      switch (output.Length % 4)
      {
        case 0: break; // No pad chars
        case 3: output += "="; break;  // One pad char
        case 2: output += "=="; break; // Two pad chars
        default: throw new FormatException(Properties.Resources.InvalidBase64);
      }

      return Convert.FromBase64String(output);
    }
  }
}
