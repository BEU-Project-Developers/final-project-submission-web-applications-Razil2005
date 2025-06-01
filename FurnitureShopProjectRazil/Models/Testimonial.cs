// Models/Testimonial.cs
using Microsoft.AspNetCore.Http; // IFormFile üçün
using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace FurnitureShopProjectRazil.Models
{
    public class Testimonial
    {
        public int Id { get; set; }

        [Required(ErrorMessage = "Ad və soyad daxil edilməlidir.")]
        [MaxLength(100, ErrorMessage = "Ad və soyad 100 simvoldan çox ola bilməz.")]
        [Display(Name = "Ad Soyad")]
        public string AuthorFullName { get; set; }

        [Required(ErrorMessage = "Vəzifə daxil edilməlidir.")]
        [MaxLength(100, ErrorMessage = "Vəzifə 100 simvoldan çox ola bilməz.")]
        [Display(Name = "Vəzifə")]
        public string AuthorTitle { get; set; }

        [Required(ErrorMessage = "Rəy mətni daxil edilməlidir.")]
        [DataType(DataType.MultilineText)]
        [Display(Name = "Rəy")]
        public string Content { get; set; }

        [Display(Name = "Şəkil Yolu")]
        public string ImagePath { get; set; } // Rəy verənin şəklinin serverdəki yolu

        [NotMapped] // Bu xüsusiyyət verilənlər bazasına yazılmayacaq
        [Display(Name = "Şəkil Yüklə")]
        public IFormFile Photo { get; set; } // Şəkil yükləmək üçün

        [Display(Name = "Paylaşılma Tarixi")]
        public DateTime DatePosted { get; set; } = DateTime.UtcNow;
    }
}