using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;

namespace JsonWebTokenWebApi.Identity
{
	public sealed class UserManagement : IUserManagement
	{
		// Singleton
		static UserManagement() { }
		private UserManagement() { }
		public static UserManagement Instance { get; } = new UserManagement();

		// Token provider
		// The key should be changed and stored securely
		private ContextualJWTProvider tokenProvider = new ContextualJWTProvider(
			issuer: "SampleSite", 
			audiences: new[] { "SampleVisitor" }, 
			tokenLifetime: 10.0,
			signingKey: "3hmu7fcnd6dfkly7urjgj3oddye1vnw0im9fyznq01hyr5ipnfxdmuj0vdnwb8jkatvb9fjfru1h7tgzemre8ubuk6gbrxgjhhucxb6pvpxbge3xakext50k98mayrrq",
			cookieKey: "qc11zioy1jzh0yxj5mirujk15z3iiqyb7jghwka4jijjkadbfjt82sjjg415oc85bu9gmz21toyghqjpppnsxlandmtsk3kx8j1ka5vsqaugiv18qcrqcb61psicvhmv"
			);

		// Placeholder for database lookup
		private UserDetails GetUserDetails(string identity, string secret)
		{
			if (identity == "admin" && secret == "secret_code") return new UserDetails { Name = "admin" };
			else return null;
		}

		// Creates a JSON Web Token
		public TokenInformation CreateSecurityToken(string identity, string secret)
		{
			// Use system to check provided login details
			var userDetails = GetUserDetails(identity, secret);

			// Return token if user details were found
			if (userDetails != null)
			{
				List<Claim> claims = new List<Claim>
				{
					new Claim(JwtRegisteredClaimNames.UniqueName, userDetails.Name),
					new Claim(JwtRegisteredClaimNames.Aud, "SampleVisitor")
				};

				return tokenProvider.CreateSecurityToken(claims);
			}

			// Return nothing on failure
			return null;
		}

		// Validate JSON Web Token
		public TokenValidationResult ValidateSecurityToken(string token, string cookie)
		{
			return tokenProvider.ValidateSecurityToken(token, cookie);
		}
	}
}