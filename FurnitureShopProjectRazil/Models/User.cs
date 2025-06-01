// Models/User.cs
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace FurnitureShopProjectRazil.Models
{
    public class User
    {
        [Key]
        public int Id { get; set; }

        [Required(ErrorMessage = "İstifadəçi adı tələb olunur.")]
        [StringLength(100, ErrorMessage = "İstifadəçi adı 3-100 simvol aralığında olmalıdır.", MinimumLength = 3)]
        public string Username { get; set; } // Modelde Username idi, qalsin

        [Required(ErrorMessage = "E-poçt ünvanı tələb olunur.")]
        [EmailAddress(ErrorMessage = "Düzgün e-poçt ünvanı daxil edin.")]
        [StringLength(256)]
        public string Email { get; set; }

        [Required(ErrorMessage = "Tam ad tələb olunur.")]
        [StringLength(150)]
        public string FullName { get; set; } // FullName olaraq deyishdirildi

        [Required]
        public byte[] PasswordHash { get; set; }

        [Required]
        public byte[] PasswordSalt { get; set; }

        public bool EmailConfirmed { get; set; } = false;
        public string? EmailConfirmationToken { get; set; } // Deyishdirildi
        public DateTime? EmailConfirmationTokenExpiry { get; set; } // Deyishdirildi

        public string? PasswordResetToken { get; set; }
        public DateTime? PasswordResetTokenExpiryDate { get; set; } // Adini PasswordResetTokenExpiry olaraq deyishecem controller ile eyni olsun

        public DateTime RegistrationDate { get; set; } = DateTime.UtcNow;

        // ImagePath User modeline elave edildi (default avatar ve profil shekli uchun)
        [MaxLength(255)]
        public string? ImagePath { get; set; }

        // PasswordResetCode ve PasswordResetCodeExpiryDate silindi, PasswordResetToken istifade olunur
        // public string? PasswordResetCode { get; set; }
        // public DateTime? PasswordResetCodeExpiryDate { get; set; }

        // Naviqasiya Propertiləri
        public virtual ICollection<UserRole> UserRoles { get; set; } = new List<UserRole>();
        public virtual UserDetails? UserDetails { get; set; } // Birə-bir əlaqə (əgər istifadə olunursa)
    }
}