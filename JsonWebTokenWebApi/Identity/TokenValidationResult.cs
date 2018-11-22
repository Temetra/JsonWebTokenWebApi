using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace JsonWebTokenWebApi.Identity
{
	public class TokenValidationResult
	{
		public ClaimsPrincipal Principle { get; set; }
		public JwtSecurityToken ValidatedToken { get; set; }
	}
}