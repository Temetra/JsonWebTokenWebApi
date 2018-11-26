using System.IdentityModel.Tokens.Jwt;

namespace JsonWebTokenWebApi.Identity
{
	public interface IUserManagement
	{
		UserDetails GetUserDetails(string identity, string secret);
		TokenInformation CreateSecurityToken(UserDetails userDetails);
		TokenValidationResult ValidateSecurityToken(TokenInformation tokenInfo);
	}
}