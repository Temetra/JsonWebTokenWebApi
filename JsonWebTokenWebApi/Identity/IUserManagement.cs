using System.IdentityModel.Tokens.Jwt;

namespace JsonWebTokenWebApi.Identity
{
	public interface IUserManagement
	{
		UserDetails GetUserDetails(string identity, string secret);
		TokenResult CreateSecurityToken(UserDetails userDetails);
		TokenValidationResult ValidateSecurityToken(string token);
	}
}