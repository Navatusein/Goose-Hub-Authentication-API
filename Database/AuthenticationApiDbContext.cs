using Microsoft.EntityFrameworkCore;

namespace AuthenticationAPI.Database
{
    /// <summary>
    /// Class context for database connection 
    /// </summary>
    public class AuthenticationApiDbContext : DbContext
    {
        /// <summary>
        /// Constructor of class AuthenticationApiDbContext
        /// </summary>
        public AuthenticationApiDbContext(DbContextOptions<AuthenticationApiDbContext> options) : base(options)
        {
            Database.EnsureCreated();
        }
    }
}
