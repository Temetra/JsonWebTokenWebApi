using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using JsonWebTokenWebApi.Identity;

namespace JsonWebTokenWebApi.Handlers
{
	public class TokenValidationHandler : DelegatingHandler
	{
		protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
		{
			// If a token and cookie are provided an attempt to authorize is made
			// If successful the request's IPrinciple is set, which is used by subsequent authorization filters
			// Throws an exception if attempt fails
			AuthorizationHelper.Instance.ProcessAuthorizationRequest(request);

			// Continue handling request
			return await base.SendAsync(request, cancellationToken);
		}
	}
}