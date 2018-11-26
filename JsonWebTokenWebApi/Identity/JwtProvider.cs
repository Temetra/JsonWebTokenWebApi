using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Collections.Generic;
using System.Text;

namespace JsonWebTokenWebApi.Identity
{
	public class JwtProvider
	{
		// JWT token handler
		private JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();

		public JwtProvider(string issuer, IEnumerable<string> audiences, double tokenLifetime, string signingKey)
		{
			Issuer = issuer;
			Audiences = audiences;
			TokenLifetime = tokenLifetime;
			SigningKey = new SymmetricSecurityKey(Encoding.Default.GetBytes(signingKey));
		}

		// Identifies the principal that issued the JWT
		private string Issuer { get; set; }

		// Specifies all valid recipients
		private IEnumerable<string> Audiences { get; set; }

		// Lifetime of token in minutes
		private double TokenLifetime { get; set; }

		// Signing key bytes
		private SymmetricSecurityKey SigningKey { get; set; }

		// Creates a JSON Web Token
		public string CreateSecurityToken(IEnumerable<Claim> claims)
		{
			// This is the content of the JSON Web Token
			ClaimsIdentity claimsIdentity = new ClaimsIdentity(claims);

			// Other claims
			var issuer = Issuer;

			// Token lifetime
			var issueDate = DateTime.UtcNow;
			var expiryDate = issueDate.AddMinutes(TokenLifetime);

			// Signing credentials
			SigningCredentials signingCredentials = new SigningCredentials(SigningKey, SecurityAlgorithms.HmacSha256Signature);

			// Create token
			JwtSecurityToken token = tokenHandler.CreateJwtSecurityToken(
				issuer: issuer,
				subject: claimsIdentity,
				notBefore: issueDate,
				expires: expiryDate,
				issuedAt: issueDate,
				signingCredentials: signingCredentials
				);

			return tokenHandler.WriteToken(token);
		}

		// Validates a JSON Web Token
		// Returns a ClaimsPrincipal or throws an exception
		public ClaimsPrincipal ValidateSecurityToken(string token, out JwtSecurityToken validatedToken)
		{
			// Other claims
			var issuer = Issuer;
			var audiences = Audiences;

			// Create validation params
			TokenValidationParameters validationParameters = new TokenValidationParameters
			{
				ValidIssuer = issuer,
				ValidAudiences = audiences,
				IssuerSigningKey = SigningKey,
				ValidateIssuer = true,
				ValidateAudience = true,
				ValidateLifetime = true,
				//ClockSkew = TimeSpan.Zero, // Default allows for +/-5 minutes on the lifetime, to compensate for server time drift
				ValidateIssuerSigningKey = true
			};

			// Validate token
			ClaimsPrincipal principle = tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedSecurityToken);

			// Return result
			validatedToken = validatedSecurityToken as JwtSecurityToken;
			return principle;
		}
	}
}