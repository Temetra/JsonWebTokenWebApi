using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace JsonWebTokenWebApi.Identity
{
	// User context used to mitigate token sidejacking
	public class ContextualJWTProvider
	{
		private JsonWebTokenProvider JwtProvider { get; set; }
		private RNGCryptoServiceProvider RngProvider { get; set; }
		private HashAlgorithm HashingAlgo { get; set; }
		private int RandomSize { get; set; }

		public ContextualJWTProvider(string issuer, IEnumerable<string> audiences, double tokenLifetime, string signingKey, string cookieKey)
		{
			JwtProvider = new JsonWebTokenProvider(issuer, audiences, tokenLifetime, signingKey);
			RngProvider = new RNGCryptoServiceProvider();
			HashingAlgo = new HMACSHA256(Encoding.Default.GetBytes(cookieKey));
			RandomSize = 64;
		}

		public TokenInformation CreateSecurityToken(ICollection<Claim> claims)
		{
			// Generate random bytes
			byte[] randomData = new byte[RandomSize];
			RngProvider.GetBytes(randomData);

			// Generate hash of context
			byte[] hashedData = HashingAlgo.ComputeHash(randomData);

			// Add hashed context to JWT claims
			claims.Add(new Claim("usr_ctx", Convert.ToBase64String(hashedData)));

			// Create security token
			string token = JwtProvider.CreateSecurityToken(claims);

			// Return result
			return new TokenInformation
			{
				Token = token,
				Cookie = Convert.ToBase64String(randomData)
			};
		}

		public TokenValidationResult ValidateSecurityToken(TokenInformation tokenInfo)
		{
			// Validate token
			TokenValidationResult tokenResult = JwtProvider.ValidateSecurityToken(tokenInfo.Token);

			// Validate user context
			if (tokenResult.ValidatedToken.Payload.TryGetValue("usr_ctx", out object tokenValue))
			{
				// Get bytes from token payload
				byte[] tokenHashed = Convert.FromBase64String(Convert.ToString(tokenValue));

				// Compute hash for cookie value
				byte[] cookieHashed = HashingAlgo.ComputeHash(Convert.FromBase64String(tokenInfo.Cookie));

				// Compare bytes
				if (tokenHashed.SequenceEqual(cookieHashed))
				{
					return tokenResult;
				}
			}

			// Cookie test failed to return value
			throw new Exception("Cookie Invalid");
		}
	}
}