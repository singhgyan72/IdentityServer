using CompanyEmployees.Client.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace CompanyEmployees.Client.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<ApplicationUser>(entity =>
            {
                entity.Property(e => e.FirstName).HasMaxLength(100);
                entity.Property(e => e.LastName).HasMaxLength(100);
                entity.Property(e => e.Country).HasMaxLength(100);
            });

            // Seed roles
            //modelBuilder.Entity<IdentityRole>().HasData(
            //    new IdentityRole
            //    {
            //        Name = "Administrator",
            //        NormalizedName = "ADMINISTRATOR",
            //        Id = "c3a0cb55-ddaf-4f2f-8419-f3f937698aa1"
            //    },
            //    new IdentityRole
            //    {
            //        Name = "User",
            //        NormalizedName = "USER",
            //        Id = "6d506b42-9fa0-4ef7-a92a-0b5b0a123665"
            //    }
            //);
        }
    }
}