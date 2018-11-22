using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Linq;

namespace JsonWebTokenWebApi.Identity
{
	public sealed class UserManagement : IUserManagement
	{
		// Singleton
		static UserManagement() { }
		private UserManagement() { }
		public static UserManagement Instance { get; } = new UserManagement();

		// JWT token handler
		private JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();

		// Placeholder for database lookup
		public UserDetails GetUserDetails(string identity, string secret)
		{
			if (identity == "admin" && secret == "secret_code") return new UserDetails { Name = "admin" };
			else return null;
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

		// Lifetime of token in minutes
		private double GetTokenLifetime()
		{
			return 10.0;
		}

		// Tokens with remaining lifetime less than this are eligible for refreshing
		private double GetLifetimeRefreshThreshold()
		{
			return 5.0;
		}

		// The key should be changed and stored securely
		private byte[] GetSigningKey()
		{
			return System.Text.Encoding.Default.GetBytes("3hmu7fcnd6dfkly7urjgj3oddye1vnw0im9fyznq01hyr5ipnfxdmuj0vdnwb8jkatvb9fjfru1h7tgzemre8ubuk6gbrxgjhhucxb6pvpxbge3xakext50k98mayrrq");
		}

		// Creates a JSON Web Token
		public string CreateSecurityToken(UserDetails userDetails)
		{
			// This is the content of the JSON Web Token
			ClaimsIdentity claimsIdentity = new ClaimsIdentity(new[]
			{
				new Claim(JwtRegisteredClaimNames.UniqueName, userDetails.Name)
			});

			// Token lifetime
			var issueDate = DateTime.UtcNow;
			var expiryDate = issueDate.AddMinutes(GetTokenLifetime());

			// Create token
			JwtSecurityToken token = tokenHandler.CreateJwtSecurityToken(
				issuer: GetIssuer(),
				audience: GetAudience(),
				subject: claimsIdentity,
				notBefore: issueDate,
				expires: expiryDate,
				issuedAt: issueDate,
				signingCredentials: GetSigningCredentials()
				);

			return tokenHandler.WriteToken(token);
		}

		// Extends the lifetime of a given token
		public bool TryRefreshingSecurityTokenLifetime(JwtSecurityToken originalToken, out string refreshedToken)
		{
			// If the lifetime is still within the threshold return null
			if (originalToken.ValidTo.Subtract(DateTime.UtcNow).TotalMinutes > GetLifetimeRefreshThreshold())
			{
				refreshedToken = null;
				return false;
			}

			// Replicate the claims identity
			ClaimsIdentity claimsIdentity = new ClaimsIdentity(new[]
			{
				originalToken.Claims.First(claim => claim.Type == JwtRegisteredClaimNames.UniqueName)
			});

			// Token lifetime
			var issueDate = originalToken.ValidFrom;
			var expiryDate = DateTime.UtcNow.AddMinutes(GetTokenLifetime());

			// Create token
			JwtSecurityToken token = tokenHandler.CreateJwtSecurityToken(
				issuer: originalToken.Issuer,
				audience: originalToken.Audiences.First(),
				subject: claimsIdentity,
				notBefore: issueDate,
				expires: expiryDate,
				issuedAt: issueDate,
				signingCredentials: GetSigningCredentials()
				);

			refreshedToken = tokenHandler.WriteToken(token);
			return true;
		}

		// Validates a JSON Web Token
		// Returns a ClaimsPrincipal or throws an exception
		public TokenValidationResult ValidateSecurityToken(string token)
		{
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

			ClaimsPrincipal principle = tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);

			return new TokenValidationResult { Principle = principle, ValidatedToken = validatedToken as JwtSecurityToken };
		}

		// Creates security key
		private SymmetricSecurityKey GetSymmetricSecurityKey()
		{
			return new SymmetricSecurityKey(GetSigningKey());
		}

		// Creates signing credentials
		private SigningCredentials GetSigningCredentials()
		{
			SymmetricSecurityKey securityKey = GetSymmetricSecurityKey();
			return new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);
		}
	}
}