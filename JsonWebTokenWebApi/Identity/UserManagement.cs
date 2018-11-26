using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace JsonWebTokenWebApi.Identity
{
	// Placeholder for database lookup
	public class UserManagement
	{
		public UserDetails GetUserDetails(string identity, string secret)
		{
			if (identity == "admin" && secret == "secret_code") return new UserDetails { Name = "admin", Audience = "SampleVisitor" };
			else return null;
		}
	}
}