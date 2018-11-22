using System.IdentityModel.Tokens.Jwt;

namespace JsonWebTokenWebApi.Identity
{
	public interface IUserManagement
	{
		UserDetails GetUserDetails(string identity, string secret);
		string CreateSecurityToken(UserDetails userDetails);
		bool TryRefreshingSecurityTokenLifetime(JwtSecurityToken originalToken, out string refreshedToken);
		TokenValidationResult ValidateSecurityToken(string token);
	}
}