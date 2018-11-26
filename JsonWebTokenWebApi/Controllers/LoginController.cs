using System.Net.Http;
using System.Web.Http;
using JsonWebTokenWebApi.Models;
using JsonWebTokenWebApi.Identity;

namespace JsonWebTokenWebApi.Controllers
{
	public class LoginController : ApiController
	{
		[HttpPost]
		public IHttpActionResult Authenticate([FromBody] LoginRequest loginRequest)
		{
			// Creates an authorization message, or Unauthorized response
			HttpResponseMessage message = AuthorizationHelper.Instance.ProcessLoginRequest(
				Request,
				loginRequest.Identity,
				loginRequest.Secret);

			// Return response
			return ResponseMessage(message);
		}
	}
}