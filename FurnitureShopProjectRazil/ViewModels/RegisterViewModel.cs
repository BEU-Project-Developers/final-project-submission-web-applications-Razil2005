using System.ComponentModel.DataAnnotations;

namespace FurnitureShopProjectRazil.ViewModels
{
    public class RegisterViewModel
    {
        [Required(ErrorMessage = "İstifadəçi adı tələb olunur.")]
        [StringLength(100, ErrorMessage = "İstifadəçi adı 3-100 simvol aralığında olmalıdır.", MinimumLength = 3)]
        [Display(Name = "İstifadəçi adı")]
        public string Username { get; set; } // Username olaraq qalsin

        [Required(ErrorMessage = "E-poçt ünvanı tələb olunur.")]
        [EmailAddress(ErrorMessage = "Düzgün e-poçt ünvanı daxil edin.")]
        [Display(Name = "E-poçt Ünvanı")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Tam ad tələb olunur.")]
        [StringLength(150, ErrorMessage = "Tam ad maksimum 150 simvol ola bilər.")]
        [Display(Name = "Tam Adınız")]
        public string FullName { get; set; } // FullName olaraq dəyişdirildi

        [Required(ErrorMessage = "Şifrə tələb olunur.")]
        [StringLength(100, ErrorMessage = "{0} ən azı {2} və ən çox {1} simvol uzunluğunda olmalıdır.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "Şifrə")]
        public string Password { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Şifrəni Təsdiqləyin")]
        [Compare("Password", ErrorMessage = "Şifrə və təsdiq şifrəsi uyğun gəlmir.")]
        public string ConfirmPassword { get; set; }
    }
}