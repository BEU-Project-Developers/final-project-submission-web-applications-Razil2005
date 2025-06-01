using System.ComponentModel.DataAnnotations;

namespace FurnitureShopProjectRazil.ViewModels
{
    public class LoginViewModel
    {
        [Required(ErrorMessage = "E-poçt və ya istifadəçi adı tələb olunur.")]
        [Display(Name = "E-poçt və ya İstifadəçi adı")]
        public string UsernameOrEmail { get; set; } // Controller-dəki ilə uyğunlaşdırıldı

        [Required(ErrorMessage = "Şifrə tələb olunur.")]
        [DataType(DataType.Password)]
        [Display(Name = "Şifrə")]
        public string Password { get; set; }

        [Display(Name = "Məni xatırla?")]
        public bool RememberMe { get; set; }
    }
}