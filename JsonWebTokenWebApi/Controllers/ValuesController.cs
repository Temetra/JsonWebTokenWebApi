using System.Collections.Generic;
using System.Web.Http;

namespace JsonWebTokenWebApi.Controllers
{
	[Authorize]
	public class ValuesController : ApiController
	{
		[AllowAnonymous]
		[Route("api/values/anon")]
		public IEnumerable<string> GetAnon()
		{
			return new string[] { "One", "Two" };
		}

		[Route("api/values/secure")]
		public IEnumerable<string> GetSecure()
		{
			return new string[] { "Three", "Four" };
		}
	}
}