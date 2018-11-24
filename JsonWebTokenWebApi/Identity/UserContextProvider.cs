using System;
using System.Security.Cryptography;
using System.Text;
using System.Linq;

namespace JsonWebTokenWebApi.Identity
{
	public class UserContextProvider
	{
		public UserContextProvider(string signingKey)
		{
			RngProvider = new RNGCryptoServiceProvider();
			HashingAlgo = new HMACSHA256(Encoding.Default.GetBytes(signingKey));
			RandomSize = 64;
		}

		private RNGCryptoServiceProvider RngProvider { get; set; }
		private HashAlgorithm HashingAlgo { get; set; }
		private int RandomSize { get; set; }

		public UserContext GenerateContext()
		{
			// Generate random bytes
			byte[] randomData = new byte[RandomSize];
			RngProvider.GetBytes(randomData);

			// Generate hash of context
			byte[] hashedData = HashingAlgo.ComputeHash(randomData);

			// Return result
			return new UserContext
			{
				Plain = Convert.ToBase64String(randomData),
				Hashed = Convert.ToBase64String(hashedData)
			};
		}

		public bool VerifyContext(UserContext context)
		{
			byte[] hashedData = Convert.FromBase64String(context.Hashed);
			byte[] rehashedData = HashingAlgo.ComputeHash(Convert.FromBase64String(context.Plain));
			return hashedData.SequenceEqual(rehashedData);
		}
	}
}