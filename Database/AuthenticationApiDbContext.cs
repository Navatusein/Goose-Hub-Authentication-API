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
        /// Constructor of class AuthenticationApiDbContext
        /// </summary>
        /// 
        public DbSet<User> Users { get; set; }
        public AuthenticationApiDbContext(DbContextOptions<AuthenticationApiDbContext> options) : base(options)
        {
            Database.EnsureCreated();
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<User>().HasData(
                new User { Id = 1, UserId = "1", Login = "admin", Email = "admin@gmail.com", PasswordHash = "#", PasswordSalt = "#", Role = "admin" }
            );
        }
    }
}
