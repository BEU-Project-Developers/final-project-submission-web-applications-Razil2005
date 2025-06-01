// ViewModels/EditProfileViewModel.cs
using Microsoft.AspNetCore.Http;
using System.ComponentModel.DataAnnotations;

// Namespace düzəldildi
namespace FurnitureShopProjectRazil.ViewModels
{
    public class EditProfileViewModel
    {
        public int UserId { get; set; }

        [Required(ErrorMessage = "İstifadəçi adı tələb olunur.")]
        [StringLength(100, ErrorMessage = "İstifadəçi adı 3-100 simvol aralığında olmalıdır.", MinimumLength = 3)]
        [Display(Name = "İstifadəçi adı")]
        public string Username { get; set; } // Username olaraq qalsin

        // Email redaktesi elave edilmeyib, sadece FullName ve Username
        // Eger email redaktesi olsa idi:
        // [Required(ErrorMessage = "E-poçt ünvanı tələb olunur.")]
        // [EmailAddress(ErrorMessage = "Düzgün e-poçt ünvanı daxil edin.")]
        // [Display(Name = "E-poçt Ünvanı")]
        // public string Email { get; set; }

        [Required(ErrorMessage = "Tam ad tələb olunur.")]
        [StringLength(150, ErrorMessage = "Tam ad maksimum 150 simvol ola bilər.")]
        [Display(Name = "Tam Adınız")]
        public string FullName { get; set; } // FullName olaraq dəyişdirildi

        [Display(Name = "Profil Şəkli")]
        public IFormFile? Photo { get; set; }

        public string? CurrentImagePath { get; set; }

        // Şifrə Dəyişikliyi Sahələri (Opsional olaraq saxlanılıb)
        // Sizin AccountController-də bunlar istifadə olunmur,
        // ChangePassword ayrıca action-dır. Bu hissəni silə bilərik
        // və ya ChangePassword View-una yönləndirən link qoya bilərik.
        // Hazırda controller-də bu sahələr yoxdur.
        /*
        [DataType(DataType.Password)]
        [Display(Name = "Hazırkı Şifrə")]
        public string? CurrentPassword { get; set; }

        [DataType(DataType.Password)]
        [StringLength(100, ErrorMessage = "{0} ən azı {2} simvol uzunluğunda olmalıdır.", MinimumLength = 6)]
        [Display(Name = "Yeni Şifrə")]
        public string? NewPassword { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Yeni Şifrəni Təsdiqləyin")]
        [Compare("NewPassword", ErrorMessage = "Yeni şifrə və təsdiq şifrəsi uyğun gəlmir.")]
        public string? ConfirmNewPassword { get; set; }
        */
    }
}