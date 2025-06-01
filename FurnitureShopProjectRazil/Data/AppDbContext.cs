using FurnitureShopProjectRazil.Models; // Bütün modelləriniz üçün
using Microsoft.EntityFrameworkCore;

namespace FurnitureShopProjectRazil.Data
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }

        // Autentifikasiya və Avtorizasiya üçün
        public DbSet<User> Users { get; set; } = null!;
        public DbSet<Role> Roles { get; set; } = null!;
        public DbSet<UserRole> UserRoles { get; set; } = null!;

        // Digər layihə modelləriniz
        public DbSet<Home> Homes { get; set; } = null!;
        public DbSet<Products> Products { get; set; } = null!; // Model adınız Products idi
        public DbSet<About> Abouts { get; set; } = null!;    // Model adınız About idi
        public DbSet<Models.Services> Services { get; set; } = null!; // Model adınız Services idi, namespace konflikti olmasın deyə
        public DbSet<Blog> Blogs { get; set; } = null!;
        public DbSet<Team> Teams { get; set; } = null!; // Team modelini əlavə etdim (əgər varsa)
        public DbSet<Testimonial> Testimonials { get; set; } = null!; // Testimonial modelini əlavə etdim (əgər varsa)
        public DbSet<UserDetails> UserDetails { get; set; } = null!;
        public DbSet<Contact> Contacts { get; set; } = null!;
        
        public DbSet<Cart> Carts { get; set; } = null!;
        public DbSet<CartItem> CartItems { get; set; } = null!;
        public DbSet<Profession> Professions { get; set; } = null!;

        // ...

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // User və Role arasında çox-çoxa (many-to-many) əlaqə UserRole vasitəsilə
            modelBuilder.Entity<UserRole>(entity =>
            {
                entity.HasKey(ur => new { ur.UserId, ur.RoleId }); // Birləşmiş Primary Key

                entity.HasOne(ur => ur.User)
                    .WithMany(u => u.UserRoles)
                    .HasForeignKey(ur => ur.UserId)
                    .OnDelete(DeleteBehavior.Cascade); // İstifadəçi silindikdə UserRole qeydləri də silinsin

                entity.HasOne(ur => ur.Role)
                    .WithMany(r => r.UserRoles)
                    .HasForeignKey(ur => ur.RoleId)
                    .OnDelete(DeleteBehavior.Cascade); // Rol silindikdə UserRole qeydləri də silinsin
            });

            // User modelindəki unikal sahələr
            modelBuilder.Entity<User>(entity =>
            {
                entity.HasIndex(u => u.Username).IsUnique();
                entity.HasIndex(u => u.Email).IsUnique();
            });

            // Role modelində RoleName unikal olmalıdır
            modelBuilder.Entity<Role>(entity =>
            {
                entity.HasIndex(r => r.Name).IsUnique();
            });

            // İlkin Rol Dataları (Seed Data) - Program.cs-də də edilə bilər, amma burada da saxlamaq olar.
            // Əgər Program.cs-də seed edirsinizsə, buranı şərhə sala bilərsiniz.
            // Amma Program.cs-də seed etmək daha çevikdir, çünki context-ə birbaşa çıxış var.
            // Mən Program.cs-də seed etməyi tövsiyə edirəm.
            /*
            modelBuilder.Entity<Role>().HasData(
                new Role { Id = 1, RoleName = "Admin" },
                new Role { Id = 2, RoleName = "Organizator" },
                new Role { Id = 3, RoleName = "User" }
            );
            */

            // Digər modelləriniz üçün əlavə konfiqurasiyalar (lazım olarsa)
            // Məsələn, Products modelində Price sahəsi stringdir, decimal olması daha yaxşıdır.
            // modelBuilder.Entity<Products>()
            //    .Property(p => p.Price)
            //    .HasColumnType("decimal(18,2)");
        }
    }
}