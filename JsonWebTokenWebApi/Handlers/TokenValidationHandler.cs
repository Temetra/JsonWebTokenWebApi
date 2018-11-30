using System;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using JsonWebTokenWebApi.Identity;
using Microsoft.IdentityModel.Tokens;

namespace JsonWebTokenWebApi.Handlers
{
	public class TokenValidationHandler : DelegatingHandler
	{
		protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
		{
			HttpResponseMessage message = null;

			try
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
			}
			catch (SecurityTokenValidationException secEx)
			{
				// An unhandled SecurityTokenValidationException results in HTTP 500
				message = request.CreateResponse(HttpStatusCode.Unauthorized, new { secEx.Message });
			}
			catch (ArgumentException argEx)
			{
				// Can happen if authorization header is invalid, results in HTTP 500
				message = request.CreateResponse(HttpStatusCode.Unauthorized, new { argEx.Message });
			}

			// Continue handling request
			if (message == null) message = await base.SendAsync(request, cancellationToken);

			// Return response
			return message;
		}
	}
}