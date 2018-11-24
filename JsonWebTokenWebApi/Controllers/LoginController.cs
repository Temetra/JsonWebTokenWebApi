using System.Net;
using System.Net.Http;
using System.Web.Http;
using JsonWebTokenWebApi.Models;
using JsonWebTokenWebApi.Identity;

namespace JsonWebTokenWebApi.Controllers
{
	public class LoginController : ApiController
	{
		// Using an example system to verify login details and create tokens
		private IUserManagement userManagement = UserManagement.Instance;

		[HttpPost]
		public IHttpActionResult Authenticate([FromBody] LoginRequest loginRequest)
		{
			HttpResponseMessage message;
			UserDetails userDetails = null;

			// Use system to check provided login details
			if (loginRequest != null)
			{
				userDetails = userManagement.GetUserDetails(
					identity: loginRequest.Identity,
					secret: loginRequest.Secret);
			}

			// Return token or refuse access
			if (userDetails != null)
			{
				TokenResult tokenResult = userManagement.CreateSecurityToken(userDetails);
				message = Request.CreateResponse(HttpStatusCode.OK, new { tokenResult.Token });
				message.Headers.Add("Set-Cookie", tokenResult.Cookie);
			}
			else
			{
				message = new HttpResponseMessage(HttpStatusCode.Unauthorized);
			}

			return ResponseMessage(message);
		}
	}
}