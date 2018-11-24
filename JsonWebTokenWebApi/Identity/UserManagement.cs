using System.IdentityModel.Tokens.Jwt;
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

		// Placeholder for database lookup
		public UserDetails GetUserDetails(string identity, string secret)
		{
			if (identity == "admin" && secret == "secret_code") return new UserDetails { Name = "admin" };
			else return null;
		}

		// Creates a JSON Web Token
		public string CreateSecurityToken(UserDetails userDetails)
		{
			// This is the content of the JSON Web Token
			var claims = new[]
			{
				new Claim(JwtRegisteredClaimNames.UniqueName, userDetails.Name),
				new Claim(JwtRegisteredClaimNames.Aud, "SampleVisitor")
			};

			// Generate token
			return tokenProvider.CreateSecurityToken(claims);
		}

		public TokenValidationResult ValidateSecurityToken(string token)
		{
			return tokenProvider.ValidateSecurityToken(token);
		}
	}
}