using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Http; // IFormFile üçün

namespace FurnitureShopProjectRazil.ViewModels
{
    public class EditProfileViewModel
    {
        [Required]
        public int UserId { get; set; } // Formda hidden olaraq ötürüləcək

        [Required(ErrorMessage = "İstifadəçi adı tələb olunur.")]
        [StringLength(50, MinimumLength = 3, ErrorMessage = "İstifadəçi adı 3 ilə 50 simvol arasında olmalıdır.")]
        [RegularExpression(@"^[a-zA-Z0-9_.-]*$", ErrorMessage = "İstifadəçi adında yalnız hərflər, rəqəmlər, alt xətt, nöqtə və tire ola bilər.")]
        [Display(Name = "İstifadəçi adı")]
        public string Username { get; set; } = string.Empty;

        [Required(ErrorMessage = "Tam ad tələb olunur.")]
        [StringLength(100, ErrorMessage = "Tam ad maksimum 100 simvol ola bilər.")]
        [Display(Name = "Adınız və Soyadınız")]
        public string Fullname { get; set; } = string.Empty;

        [Display(Name = "Profil Şəkli")]
        // Opsional: Fayl ölçüsü və tipi üçün validation əlavə edə bilərsiniz
        // [MaxFileSize(5 * 1024 * 1024)] // Məsələn, 5 MB
        // [AllowedExtensions(new string[] { ".jpg", ".jpeg", ".png" })]
        public IFormFile? Photo { get; set; } // Yeni şəkil yükləmək üçün

        public string? CurrentImagePath { get; set; } // Mövcud şəklin yolunu View-da göstərmək üçün
    }
}