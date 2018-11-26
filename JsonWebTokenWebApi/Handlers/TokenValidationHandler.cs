using System.Net.Http;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using JsonWebTokenWebApi.Identity;

namespace JsonWebTokenWebApi.Handlers
{
	public class TokenValidationHandler : DelegatingHandler
	{
		protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
		{
			// If a token and cookie are provided an attempt to authorize is made
			// Throws an exception if attempt fails
			ClaimsPrincipal principle = AuthorizationHelper.Instance.ProcessAuthorizationRequest(request);

			// Set Principle, which is used by subsequent authorization filters
			if (principle != null)
			{
				Thread.CurrentPrincipal = principle;
				HttpContext.Current.User = principle;
			}

			// Continue handling request
			return await base.SendAsync(request, cancellationToken);
		}
	}
}