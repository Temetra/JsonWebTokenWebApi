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
using System.Net.Http.Headers;

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

			// Get token and cookie from headers
			string token = GetTokenFromHeaders(request);
			string cookie = GetCookieFromHeaders(request);

			if (string.IsNullOrEmpty(token) == false && string.IsNullOrEmpty(cookie) == false)
			{
				try
				{
					// Validate the token, getting a ClaimsPrinciple
					validationResult = userManagement.ValidateSecurityToken(token, cookie);

					// If successful, set the principle to be used by the request handlers
					Thread.CurrentPrincipal = validationResult.Principle;
					HttpContext.Current.User = validationResult.Principle;
				}
				catch (SecurityTokenValidationException secEx)
				{
					// An unhandled SecurityTokenValidationException results in HTTP 500
					message = request.CreateResponse(HttpStatusCode.Unauthorized, new { secEx.Message });
				}
				catch (ArgumentException argEx)
				{
					message = request.CreateResponse(HttpStatusCode.Unauthorized, new { argEx.Message });
				}
			}

			// Handle the request if error response is empty
			if (message == null)
			{
				message = await base.SendAsync(request, cancellationToken);
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

		private string GetCookieFromHeaders(HttpRequestMessage request)
		{
			CookieHeaderValue cookie = request.Headers.GetCookies("__Secure-usr_ctx").FirstOrDefault();
			if (cookie != null) return cookie["__Secure-usr_ctx"].Value;
			else return null;
		}
	}
}