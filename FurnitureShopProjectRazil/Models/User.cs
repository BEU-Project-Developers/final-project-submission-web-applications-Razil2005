// Models/User.cs
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Collections.Generic; // List üçün

namespace FurnitureShopProjectRazil.Models
{
    public class User
    {
        public int Id { get; set; }

        [MaxLength(255)]
        public string? ImagePath { get; set; } // Qeydiyyatda default, sonra dəyişə bilər

        [NotMapped]
        public IFormFile? Photo { get; set; }

        [Required(ErrorMessage = "İstifadəçi adı tələb olunur")]
        [MaxLength(50)]
        public string Username { get; set; } = null!;

        [Required(ErrorMessage = "Tam ad tələb olunur")]
        [MaxLength(100)]
        public string Fullname { get; set; } = null!;

        [Required(ErrorMessage = "E-poçt ünvanı tələb olunur")]
        [MaxLength(100)]
        [EmailAddress(ErrorMessage = "Düzgün e-poçt formatı daxil edin")]
        public string Email { get; set; } = null!;

        public bool EmailConfirmed { get; set; } = false;

        // IPasswordService ilə idarə olunacaq
        public byte[]? PasswordHash { get; set; }
        public byte[]? PasswordSalt { get; set; }

        // Tokenlər
        public string? EmailConfirmationToken { get; set; }
        public DateTime? EmailConfirmationTokenExpiry { get; set; }

        public string? PasswordResetToken { get; set; }
        public DateTime? PasswordResetTokenExpiry { get; set; }

        public List<UserRole> UserRoles { get; set; } = new List<UserRole>();
    }
}

// Models/Role.cs və Models/UserRole.cs əvvəlki kimi qalır.