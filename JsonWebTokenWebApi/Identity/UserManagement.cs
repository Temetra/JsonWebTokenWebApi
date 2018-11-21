using Microsoft.IdentityModel.Tokens;
using System;
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
			ClaimsIdentity claimsIdentity = new ClaimsIdentity(new[]
			{
				new Claim(ClaimTypes.Name, userDetails.Name)
			});

			// Create token
			JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();

			JwtSecurityToken token = tokenHandler.CreateJwtSecurityToken(
				issuer: GetIssuer(),
				audience: GetAudience(),
				subject: claimsIdentity,
				notBefore: GetIssueDate(),
				expires: GetExpiryDate(),
				signingCredentials: GetSigningCredentials()
				);

			return tokenHandler.WriteToken(token);
		}

		// Validates a JSON Web Token
		// Returns a ClaimsPrincipal or throws an exception
		public ClaimsPrincipal ValidateSecurityToken(string token)
		{
			JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();

			TokenValidationParameters validationParameters = new TokenValidationParameters
			{
				ValidIssuer = GetIssuer(),
				ValidAudiences = GetAudiences(),
				IssuerSigningKey = GetSymmetricSecurityKey(),
				ValidateIssuer = true,
				ValidateAudience = true,
				ValidateLifetime = true,
				//ClockSkew = TimeSpan.Zero, // Default allows for +/-5 minutes on the lifetime, to compensate for server time drift
				ValidateIssuerSigningKey = true
			};

			return handler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);
		}

		// Identifies the principal that issued the JWT
		private string GetIssuer()
		{
			return "http://localhost:58595";
		}

		// Identifies the recipients that the JWT is intended for
		private string GetAudience()
		{
			return "http://localhost:58595";
		}

		// Specifies all valid recipients
		private string[] GetAudiences()
		{
			return new[] { "http://localhost:58595" };
		}

		// Returns issue date for a new JSON Web Token
		private DateTime GetIssueDate()
		{
			return DateTime.UtcNow;
		}

		// Returns expiry date for a new JSON Web Token
		private DateTime GetExpiryDate()
		{
			return DateTime.UtcNow.AddDays(7);
		}

		// Creates security key
		private SymmetricSecurityKey GetSymmetricSecurityKey()
		{
			// The key should be changed and stored securely
			string key = "3hmu7fcnd6dfkly7urjgj3oddye1vnw0im9fyznq01hyr5ipnfxdmuj0vdnwb8jkatvb9fjfru1h7tgzemre8ubuk6gbrxgjhhucxb6pvpxbge3xakext50k98mayrrq";
			return new SymmetricSecurityKey(System.Text.Encoding.Default.GetBytes(key));
		}

		// Creates signing credentials
		private SigningCredentials GetSigningCredentials()
		{
			SymmetricSecurityKey securityKey = GetSymmetricSecurityKey();
			return new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);
		}
	}
}