﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.34014
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace Jack.Properties {
    using System;
    
    
    /// <summary>
    ///   A strongly-typed resource class, for looking up localized strings, etc.
    /// </summary>
    // This class was auto-generated by the StronglyTypedResourceBuilder
    // class via a tool like ResGen or Visual Studio.
    // To add or remove a member, edit your .ResX file then rerun ResGen
    // with the /str option, or rebuild your VS project.
    [global::System.CodeDom.Compiler.GeneratedCodeAttribute("System.Resources.Tools.StronglyTypedResourceBuilder", "4.0.0.0")]
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute()]
    [global::System.Runtime.CompilerServices.CompilerGeneratedAttribute()]
    internal class Resources {
        
        private static global::System.Resources.ResourceManager resourceMan;
        
        private static global::System.Globalization.CultureInfo resourceCulture;
        
        [global::System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1811:AvoidUncalledPrivateCode")]
        internal Resources() {
        }
        
        /// <summary>
        ///   Returns the cached ResourceManager instance used by this class.
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        internal static global::System.Resources.ResourceManager ResourceManager {
            get {
                if (object.ReferenceEquals(resourceMan, null)) {
                    global::System.Resources.ResourceManager temp = new global::System.Resources.ResourceManager("Jack.Properties.Resources", typeof(Resources).Assembly);
                    resourceMan = temp;
                }
                return resourceMan;
            }
        }
        
        /// <summary>
        ///   Overrides the current thread's CurrentUICulture property for all
        ///   resource lookups using this strongly typed resource class.
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        internal static global::System.Globalization.CultureInfo Culture {
            get {
                return resourceCulture;
            }
            set {
                resourceCulture = value;
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The signature algorithm is invalid..
        /// </summary>
        internal static string BadAlgorithm {
            get {
                return ResourceManager.GetString("BadAlgorithm", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The client identifier is invalid..
        /// </summary>
        internal static string BadClient {
            get {
                return ResourceManager.GetString("BadClient", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The origin is not allowed..
        /// </summary>
        internal static string BadOrigin {
            get {
                return ResourceManager.GetString("BadOrigin", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The signature cannot be verified..
        /// </summary>
        internal static string BadSignature {
            get {
                return ResourceManager.GetString("BadSignature", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The access token is malformed..
        /// </summary>
        internal static string BadToken {
            get {
                return ResourceManager.GetString("BadToken", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Invalid Base32 string..
        /// </summary>
        internal static string InvalidBase32 {
            get {
                return ResourceManager.GetString("InvalidBase32", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Invalid Base64 string..
        /// </summary>
        internal static string InvalidBase64 {
            get {
                return ResourceManager.GetString("InvalidBase64", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The JWT is not formatted correctly..
        /// </summary>
        internal static string InvalidJwt {
            get {
                return ResourceManager.GetString("InvalidJwt", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The specified algorithm is not supported..
        /// </summary>
        internal static string InvalidJwtAlgorithm {
            get {
                return ResourceManager.GetString("InvalidJwtAlgorithm", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The resource does not exist..
        /// </summary>
        internal static string NotFound {
            get {
                return ResourceManager.GetString("NotFound", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to No access token was specified..
        /// </summary>
        internal static string Unauthorized {
            get {
                return ResourceManager.GetString("Unauthorized", resourceCulture);
            }
        }
    }
}