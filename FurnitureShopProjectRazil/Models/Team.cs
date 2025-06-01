using Microsoft.AspNetCore.Http; // IFormFile üçün
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace FurnitureShopProjectRazil.Models
{
    public class Team
    {
        public int Id { get; set; }

        [Required]
        [MaxLength(100)] // Məntiqli bir uzunluq təyin edin
        public string Fullname { get; set; }

        public string ImagePath { get; set; } // Şəklin serverdəki yolu

        [NotMapped] // Bu xüsusiyyət verilənlər bazasına yazılmayacaq
        public IFormFile Photo { get; set; } // Şəkil yükləmək üçün

        [Required] // Bioqrafiya məcburi olsun
        public string Biography { get; set; }

        public string PersonalNote { get; set; } // Bu sahə əvvəlki HTML-də yox idi, amma modeldə var. İstəsəniz View-da istifadə edə bilərsiniz.

        // Foreign Key for Profession
        [Required] // Hər komanda üzvünün bir peşəsi olmalıdır
        public int ProfessionId { get; set; }

        // Navigation Property
        public Profession Profession { get; set; }
    }
}