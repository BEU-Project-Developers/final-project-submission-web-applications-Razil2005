using System.ComponentModel.DataAnnotations;

namespace FurnitureShopProjectRazil.ViewModels
{
    public class ResetPasswordViewModel
    {
        [Required]
        public string UserId { get; set; } // string olaraq saxlanılır, çünki URL-dən gəlir

        [Required]
        public string Token { get; set; } // URL üçün kodlanmış token

        [Required(ErrorMessage = "Yeni şifrə tələb olunur.")]
        [StringLength(100, ErrorMessage = "{0} ən azı {2} simvol uzunluğunda olmalıdır.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "Yeni Şifrə")]
        public string Password { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Yeni Şifrəni Təsdiqləyin")]
        [Compare("Password", ErrorMessage = "Şifrə və təsdiq şifrəsi uyğun gəlmir.")]
        public string ConfirmPassword { get; set; }
    }
}