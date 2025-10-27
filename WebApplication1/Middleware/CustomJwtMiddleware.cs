using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;

namespace WebApplication1.Middleware
{
    public class CustomJwtMiddleware
    {
        private readonly RequestDelegate _next;

        public CustomJwtMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext context)
        {
            Console.WriteLine($"Request: {context.Request.Method} {context.Request.Path}");
            // Optionally: log body, headers, remote IP, etc.
            await _next(context);
        }
    }
}
