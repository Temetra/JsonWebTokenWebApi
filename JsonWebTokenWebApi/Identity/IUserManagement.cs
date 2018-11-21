using System.Security.Claims;

namespace JsonWebTokenWebApi.Identity
{
	public interface IUserManagement
	{
		UserDetails GetUserDetails(string identity, string secret);
		string CreateSecurityToken(UserDetails userDetails);
		ClaimsPrincipal ValidateSecurityToken(string token);
	}
}