﻿using Microsoft.IdentityModel.Tokens;
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

		protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
		{
			// Used to send a custom error to the client
			HttpResponseMessage message = null;

			// Get the token from the Authorization header
			string token = GetTokenFromHeaders(request);

			if (string.IsNullOrEmpty(token) == false)
			{
				try
				{
					// Validate the token, getting a ClaimsPrinciple
					var principle = userManagement.ValidateSecurityToken(token);

					// If successful, set the principle to be used by the request handlers
					Thread.CurrentPrincipal = principle;
					HttpContext.Current.User = principle;
				}
				catch (SecurityTokenValidationException secEx)
				{
					// An unhandled SecurityTokenValidationException results in HTTP 500
					message = request.CreateResponse(HttpStatusCode.Unauthorized, new { secEx.Message });
				}
			}

			// Return the custom error message, or handle the request
			if (message != null) return Task<HttpResponseMessage>.Factory.StartNew(() => message);
			else return base.SendAsync(request, cancellationToken);
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