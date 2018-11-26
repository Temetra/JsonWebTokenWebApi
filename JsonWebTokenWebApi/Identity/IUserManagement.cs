using System.IdentityModel.Tokens.Jwt;

namespace JsonWebTokenWebApi.Identity
{
	public interface IUserManagement
	{
		TokenInformation CreateSecurityToken(string identity, string secret);
		TokenValidationResult ValidateSecurityToken(string token, string cookie);
	}
}