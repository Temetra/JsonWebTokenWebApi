using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace JsonWebTokenWebApi.Identity
{
	// Adds user context to mitigate token sidejacking
	public class ContextualJwtProvider
	{
		private JwtProvider JwtProvider { get; set; }
		private RNGCryptoServiceProvider RngProvider { get; set; }
		private HashAlgorithm HashingAlgo { get; set; }
		private int RandomSize { get; set; }
		private string ContextClaimName { get; set; }

		public ContextualJwtProvider(string issuer, IEnumerable<string> audiences, double tokenLifetime, string signingKey, string cookieKey, string contextClaimName)
		{
			JwtProvider = new JwtProvider(issuer, audiences, tokenLifetime, signingKey);
			RngProvider = new RNGCryptoServiceProvider();
			HashingAlgo = new HMACSHA256(Encoding.Default.GetBytes(cookieKey));
			RandomSize = 64;
			ContextClaimName = contextClaimName;
		}

		public ContextualizedToken CreateSecurityToken(ICollection<Claim> claims)
		{
			// Generate random bytes
			byte[] randomData = new byte[RandomSize];
			RngProvider.GetBytes(randomData);

			// Generate hash of context
			byte[] hashedData = HashingAlgo.ComputeHash(randomData);

			// Add hashed context to JWT claims
			claims.Add(new Claim(ContextClaimName, Convert.ToBase64String(hashedData)));

			// Create security token
			string token = JwtProvider.CreateSecurityToken(claims);

			// Return result
			return new ContextualizedToken
			{
				Token = token,
				Cookie = Convert.ToBase64String(randomData)
			};
		}

		// Returns a ClaimsPrincipal or throws an exception
		public ClaimsPrincipal ValidateSecurityToken(string token, string cookie)
		{
			// Validate token
			ClaimsPrincipal principle = JwtProvider.ValidateSecurityToken(token, out JwtSecurityToken validatedToken);

			// Validate user context
			if (validatedToken.Payload.TryGetValue(ContextClaimName, out object tokenValue))
			{
				// Get bytes from token payload
				byte[] tokenHashed = Convert.FromBase64String(Convert.ToString(tokenValue));

				// Compute hash for cookie value
				byte[] cookieHashed = HashingAlgo.ComputeHash(Convert.FromBase64String(cookie));

				// Compare bytes
				if (tokenHashed.SequenceEqual(cookieHashed))
				{
					return principle;
				}
			}

			// Cookie test failed to return value
			throw new SecurityTokenValidationException("User context invalid");
		}
	}
}