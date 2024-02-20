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
                new User { Id = 1, UserId = Guid.NewGuid().ToString(), Login = "admin", Email = "admin@gmail.com",
                    PasswordHash = "b/lao4cN7vqqSfENoxCzfXYuLPZYmfDCH19wdgjjtNcbSxA8DoMxz9PwXWE+iW4ULYy2bG5ht/mOb9nGN3ZyGQ==",
                    PasswordSalt = "iTy6CMGkWESCUnpDP98CIWCKw79dJeGogCXUIVF11a8oSsjddmgCdRUymDrbDHpbTslAT//wfKOW8Z6Oox2Wdc1jV1IYooy0a2XUVDtIgx7csgzubcYfaOlHehgbQELphZ94S+BhjzkBsueL0H0yMJMJlrHERe6xh297V6WsASQ=",
                    Role = "admin"}, // password - adminadmin
                new User { Id = 2, UserId = Guid.NewGuid().ToString(), Login = "hrundel12", Email = "hrundel12@gmail.com",
                    PasswordHash = "OHfmIykA+lR5dy1g/dW6ktdfqHVM0IDIN21MnyYOjIsbXiEMVLZQVldn5JQBHMcGYSuGPWCT6uIhFE6gd47JvQ==",
                    PasswordSalt = "0NKrAF1TvQW3N+V7vG53isFMvYoW+gOH55qoH8trMS/Unxu/eJ2/osaHXaiEeMCktUlaWHzVEdsJqFUMX65TcPYFCjzzTj333bAHg0FQRg/9hmUsx3X46z/yf0M+nw1vSyQLibj3YAFOcZg78ntiwFJ7HOm9SZUWsD1Zs4aEDYU=",
                    Role = "user" } // password - 123123

            );
        }
    }
}
