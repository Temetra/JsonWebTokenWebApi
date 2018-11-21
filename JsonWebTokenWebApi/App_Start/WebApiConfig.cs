using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Http;

namespace JsonWebTokenWebApi
{
	public static class WebApiConfig
	{
		public static void Register(HttpConfiguration config)
		{
			// Web API configuration and services
			config.MessageHandlers.Add(new Handlers.TokenValidationHandler());

			// Only show exception details for local requests
			config.IncludeErrorDetailPolicy = IncludeErrorDetailPolicy.LocalOnly;

			// Web API routes
			config.MapHttpAttributeRoutes();

			config.Routes.MapHttpRoute(
				name: "DefaultApi",
				routeTemplate: "api/{controller}/{id}",
				defaults: new { id = RouteParameter.Optional }
			);
		}
	}
}
