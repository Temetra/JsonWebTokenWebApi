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
			// Response message
			HttpResponseMessage message;

			// Attempt to create token for provided credentials
			TokenInformation tokenResult = userManagement.CreateSecurityToken(
				identity: loginRequest.Identity,
				secret: loginRequest.Secret);

			// Return token or refuse access
			if (tokenResult != null)
			{
				// Create response with token as body
				message = Request.CreateResponse(HttpStatusCode.OK, new { tokenResult.Token });

				// Set secure cookie
				CookieHeaderValue cookie = new CookieHeaderValue("__Secure-usr_ctx", tokenResult.Cookie);
				cookie.Secure = true;
				cookie.HttpOnly = true;
				cookie.MaxAge = System.TimeSpan.FromMinutes(10);
				message.Headers.AddCookies(new[] { cookie });
			}
			else
			{
				message = new HttpResponseMessage(HttpStatusCode.Unauthorized);
			}

			// Return response
			return ResponseMessage(message);
		}
	}
}