using Microsoft.EntityFrameworkCore;
using AuthenticationAPI.Database.Models;

namespace AuthenticationAPI.Database
{
    /// <summary>
    /// Class context for database connection 
    /// </summary>
    public class AuthenticationApiDbContext : DbContext
    {
        /// <summary>
        /// Gets or Sets Users
        /// </summary>
        public DbSet<User> Users { get; set; }

        /// <summary>
        /// Constructor
        /// </summary>
        public AuthenticationApiDbContext(DbContextOptions<AuthenticationApiDbContext> options) : base(options)
        {
            Database.EnsureCreated();
        }
    }
}
