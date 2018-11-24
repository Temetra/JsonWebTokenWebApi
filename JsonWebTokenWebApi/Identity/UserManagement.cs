using System;
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
		private JsonWebTokenProvider tokenProvider = new JsonWebTokenProvider(
			issuer: "SampleSite", 
			audiences: new[] { "SampleVisitor" }, 
			tokenLifetime: 10.0,
			signingKey: "3hmu7fcnd6dfkly7urjgj3oddye1vnw0im9fyznq01hyr5ipnfxdmuj0vdnwb8jkatvb9fjfru1h7tgzemre8ubuk6gbrxgjhhucxb6pvpxbge3xakext50k98mayrrq"
			);

		// User context provider
		// Used to mitigate token sidejacking
		private UserContextProvider contextProvider = new UserContextProvider(
			signingKey: "qc11zioy1jzh0yxj5mirujk15z3iiqyb7jghwka4jijjkadbfjt82sjjg415oc85bu9gmz21toyghqjpppnsxlandmtsk3kx8j1ka5vsqaugiv18qcrqcb61psicvhmv"
			);

		// Placeholder for database lookup
		public UserDetails GetUserDetails(string identity, string secret)
		{
			if (identity == "admin" && secret == "secret_code") return new UserDetails { Name = "admin" };
			else return null;
		}

		// Creates a JSON Web Token
		public TokenResult CreateSecurityToken(UserDetails userDetails)
		{
			// User context
			UserContext context = contextProvider.GenerateContext();

			// Generate token
			string token = tokenProvider.CreateSecurityToken(new[]
			{
				new Claim(JwtRegisteredClaimNames.UniqueName, userDetails.Name),
				new Claim(JwtRegisteredClaimNames.Aud, "SampleVisitor"),
				new Claim("user_context", context.Hashed)
			});

			// Generate cookie
			string cookie = "__Secure-uctx=" + context.Plain + "; Max-Age=600; Secure; HttpOnly; SameSite=Strict";

			// Return result
			return new TokenResult
			{
				Token = token,
				Cookie = cookie
			};
		}

		public TokenValidationResult ValidateSecurityToken(string token)
		{
			return tokenProvider.ValidateSecurityToken(token);
		}
	}
}