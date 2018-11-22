using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using JsonWebTokenWebApi.Identity;

namespace JsonWebTokenWebApi.Handlers
{
	public class TokenValidationHandler : DelegatingHandler
	{
		// Using an example system to verify login details and create tokens
		private IUserManagement userManagement = UserManagement.Instance;

		protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
		{
			// Used to send a custom error to the client
			HttpResponseMessage message = null;
			TokenValidationResult validationResult = null;
			string refreshedToken = null;

			// Get the token from the Authorization header
			string token = GetTokenFromHeaders(request);

			if (string.IsNullOrEmpty(token) == false)
			{
				try
				{
					// Validate the token, getting a ClaimsPrinciple
					validationResult = userManagement.ValidateSecurityToken(token);

					// If the lifetime is close to ending, extend the expiry
					userManagement.TryRefreshingSecurityTokenLifetime(validationResult.ValidatedToken, out refreshedToken);

					// If successful, set the principle to be used by the request handlers
					Thread.CurrentPrincipal = validationResult.Principle;
					HttpContext.Current.User = validationResult.Principle;
				}
				catch (SecurityTokenValidationException secEx)
				{
					// An unhandled SecurityTokenValidationException results in HTTP 500
					message = request.CreateResponse(HttpStatusCode.Unauthorized, new { secEx.Message });
				}
			}

			// Handle the request if error response is empty
			if (message == null)
			{
				message = await base.SendAsync(request, cancellationToken);
			}

			// Add sliding session token to header
			if (refreshedToken != null)
			{
				message.Headers.Add("Authorization", "Bearer " + refreshedToken);
			}

			// Return response
			return message;
		}

		private string GetTokenFromHeaders(HttpRequestMessage request)
		{
			// RFC: Multiple message-header fields with the same field - name MAY be present in a message 
			// if and only if the entire field-value for that header field is defined as a comma - separated list
			// In this case, Authorization only has one value
			// Token is given as follows: Authorization: <type> <credentials>
			// JWT uses Bearer as the type
			if (request.Headers.TryGetValues("Authorization", out IEnumerable<string> authHeaders))
			{
				var authValue = authHeaders.First().Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);

				if (authValue != null && authValue.Count() == 2 && authValue[0] == "Bearer")
				{
					return authValue[1];
				}
			}

			return null;
		}
	}
}