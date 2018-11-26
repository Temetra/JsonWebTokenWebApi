using System.Net;
using System.Net.Http;
using System.Web.Http;
using JsonWebTokenWebApi.Models;
using JsonWebTokenWebApi.Identity;
using System.Net.Http.Headers;

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
				// Create token
				TokenInformation tokenResult = userManagement.CreateSecurityToken(userDetails);

				// Create response with token as body
				message = Request.CreateResponse(HttpStatusCode.OK, new { tokenResult.Token });

				// Set secure cookie
				var cookie = new CookieHeaderValue("__Secure-usr_ctx", tokenResult.Cookie);
				cookie.Secure = true;
				cookie.HttpOnly = true;
				cookie.MaxAge = System.TimeSpan.FromMinutes(10);
				message.Headers.AddCookies(new[] { cookie });
			}
			else
			{
				message = new HttpResponseMessage(HttpStatusCode.Unauthorized);
			}

			return ResponseMessage(message);
		}
	}
}