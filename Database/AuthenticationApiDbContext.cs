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
            User admin = new User()
            {
                Id = 1,
                UserId = Guid.NewGuid().ToString(), // 808aabe2-791b-472d-ae50-f293e9eaa372
                Login = "admin",
                Email = "admin@gmail.com",
                Role = "Admin"
            };
            admin.CreatePasswordHash("adminadmin");

            User user = new User()
            {
                Id = 2,
                UserId = Guid.NewGuid().ToString(),
                Login = "hrundel12",
                Email = "hrundel12@gmail.com",
                Role = "User"
            };
            user.CreatePasswordHash("123123");

            modelBuilder.Entity<User>().HasData(
                admin,
                user
            );
        }
    }
}
