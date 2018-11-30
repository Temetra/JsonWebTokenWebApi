using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;

namespace JsonWebTokenWebApi.Identity
{
	public sealed class AuthorizationHelper
	{
		// Singleton
		static AuthorizationHelper() { }
		public static AuthorizationHelper Instance { get; } = new AuthorizationHelper();

		// Properties
		private double TokenLifetime { get; set; }
		private string ContextCookieName { get; set; }
		private UserManagement UserProvider { get; set; }
		private ContextualJwtProvider TokenProvider { get; set; }

		// Keys should be changed and stored securely
		private AuthorizationHelper()
		{
			TokenLifetime = 10.0;
			ContextCookieName = "__Secure-usr_ctx";
			UserProvider = new UserManagement();
			TokenProvider = new ContextualJwtProvider(
				issuer: "SampleSite",
				audiences: new[] { "SampleVisitor" },
				tokenLifetime: TokenLifetime,
				signingKey: "3hmu7fcnd6dfkly7urjgj3oddye1vnw0im9fyznq01hyr5ipnfxdmuj0vdnwb8jkatvb9fjfru1h7tgzemre8ubuk6gbrxgjhhucxb6pvpxbge3xakext50k98mayrrq",
				cookieKey: "qc11zioy1jzh0yxj5mirujk15z3iiqyb7jghwka4jijjkadbfjt82sjjg415oc85bu9gmz21toyghqjpppnsxlandmtsk3kx8j1ka5vsqaugiv18qcrqcb61psicvhmv",
				contextClaimName: "usr_ctx"
			);
		}

		public HttpResponseMessage ProcessLoginRequest(HttpRequestMessage request, string identity, string secret)
		{
			// Use system to check provided login details
			var userDetails = UserProvider.GetUserDetails(identity, secret);

			// Return failure if user was not found
			if (userDetails == null)
			{
				return new HttpResponseMessage(HttpStatusCode.Unauthorized);
			}

			// Create token claims based on user details
			List<Claim> claims = new List<Claim>
			{
				new Claim(JwtRegisteredClaimNames.UniqueName, userDetails.Name),
				new Claim(JwtRegisteredClaimNames.Aud, userDetails.Audience)
			};

			// Create token
			ContextualizedToken tokenResult = TokenProvider.CreateSecurityToken(claims);

			// Create response with token as body
			HttpResponseMessage message = request.CreateResponse(HttpStatusCode.OK, new { tokenResult.Token });

			// Set secure cookie
			CookieHeaderValue cookie = new CookieHeaderValue(ContextCookieName, tokenResult.Cookie)
			{
				Secure = true,
				HttpOnly = true,
				MaxAge = TimeSpan.FromMinutes(TokenLifetime),
				Path = "/"
			};
			message.Headers.AddCookies(new[] { cookie });

			// Return success
			return message;
		}

		// If a token and cookie are provided an attempt to authorize is made
		public ClaimsPrincipal ProcessAuthorizationRequest(HttpRequestMessage request)
		{
			// Get token from headers
			string token = GetTokenFromHeaders(request);
			if (string.IsNullOrEmpty(token)) return null;

			// Get cookie from headers
			string cookie = GetCookieFromHeaders(request);
			if (string.IsNullOrEmpty(cookie)) return null;

			// Validate the token, getting a ClaimsPrinciple
			return TokenProvider.ValidateSecurityToken(token, cookie);
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
			CookieHeaderValue cookie = request.Headers.GetCookies(ContextCookieName).FirstOrDefault();
			if (cookie != null) return cookie[ContextCookieName].Value;
			else return null;
		}
	}
}